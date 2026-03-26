import os
import hashlib
import time
import io
import zipfile
import base64
from urllib.parse import urljoin

import requests  # para obtener ZIP de screenshots

from ..cuckoo.cuckoo import CTASCuckoo

HAS_CUCKOO = True
try:
    # noinspection PyUnresolvedReferences
    from cuckoo_api_handler import Cuckoo
except ImportError:
    HAS_CUCKOO = False


class CTASCape(CTASCuckoo):
    name = 'sandbox_cape'
    description = 'Submit file to CAPE Sandbox.'
    acts_on = ['nullsoft_installer', 'executable', 'word', 'html', 'rtf', 'excel', 'pdf', 'javascript', 'jar',
               'powerpoint', 'vbs']
    triggered_by = ['*(sandbox_cape)', '*(all_sandboxes)', '*(free_sandboxes)']

    config = [
        {'name': 'api_endpoint', 'type': 'str',
         'default': 'https://mal-prod-cape.immunityinc.com/apiv2/',
         'description': 'URL de la API de CAPE (use /apiv2/).'},
        {'name': 'api_token', 'type': 'str', 'default': '',
         'description': 'Token de API de CAPE (DRF TokenAuthentication).'},
        {'name': 'verify_ssl', 'type': 'bool', 'default': True,
         'description': 'Verificar certificado SSL al hablar con CAPE.'},
        {'name': 'ignore_failures', 'type': 'bool', 'default': True,
         'description': 'Si el análisis falla en CAPE, no lanzar excepción y devolver el task_id igualmente.'},
        {'name': 'web_endpoint', 'type': 'str',
         'default': 'https://mal-prod-cape.immunityinc.com/',
         'description': 'URL de la interfaz web de CAPE.'},
        {'name': 'wait_timeout', 'type': 'integer', 'default': 5400,
         'description': 'Tiempo en segundos que esperará a que termine el análisis.'},
        {'name': 'wait_step', 'type': 'integer', 'default': 30,
         'description': 'Intervalo en segundos entre chequeos de estado del análisis.'},
        {'name': 'analysis_time', 'type': 'integer', 'default': 300,
         'description': 'Tiempo (en segundos) durante el cual se analizará la muestra.'},
        {
            'name': 'first_wait',
            'type': 'integer',
            'default': 430,  # 7m05s
            'description': 'Primer sleep (s) antes de comenzar a consultar el estado tras subir la muestra.'
        },
    ]

    permissions = {
        'cape_access': 'For users that have access to the Cuckoo Sandbox instance. Will display a link to the analysis.'
    }

    parse_format = {
        'iocs': {
            'association': {'URL': ['target.file.urls.item']},
            'behaviour': {
                'URL': ['network.http.item.uri', 'metadata.cfgextr.item.url.item'],
                'Mutex': ['behavior.summary.mutexes.item'],
                'Registry Key': ['behavior.summary.write_keys.item'],
                'Address': ['network.udp.item.dst', 'network.tcp.item.dst'],
                'Host': ['network.domains.item.domain'],
            }
        },
        'attributes': {
            'sha512': 'target.file.sha512',
            'pe.debug_symbol_path': 'static.pe.pdbpath',
            'pe.import_hash': 'static.pe.imphash',
            'pe.timestamp': 'static.pe.timestamp'
        }
    }

    # -------------------------------- util HTTP --------------------------------

    def _full_url(self, path: str) -> str:
        return urljoin(self.api_endpoint, path)

    def _log_api(self, method: str, path: str, extra: str = ""):
        self.log('info', f'HTTP {method} {self._full_url(path)}{extra}')

    def _make_client(self):
        self.log('info', f'Inicializando cliente CAPE v3.12: base={self.api_endpoint} verify_ssl={getattr(self, "verify_ssl", True)}')
        cuckoo = Cuckoo(self.api_endpoint, cape=True)

        token = (getattr(self, 'api_token', '') or '').strip()
        try:
            if token:
                if hasattr(cuckoo, "session"):
                    cuckoo.session.headers.update({"Authorization": f"Token {token}"})
                else:
                    if not hasattr(cuckoo, "headers"):
                        setattr(cuckoo, "headers", {})
                    cuckoo.headers["Authorization"] = f"Token {token}"
                self.log('info', 'Auth: usando Token en Authorization')
            else:
                self.log('info', 'Auth: sin Token')
        except Exception as e:
            self.log('warning', f'No se pudo adjuntar Authorization: {e}')

        try:
            if hasattr(cuckoo, "session") and hasattr(self, 'verify_ssl'):
                cuckoo.session.verify = bool(self.verify_ssl)
        except Exception as e:
            self.log('warning', f'No se pudo ajustar verify SSL: {e}')
        return cuckoo

    def _get_session(self, cuckoo):
        """Devuelve la sesión del cliente cuckoo si existe, o crea una nueva con el token configurado."""
        if hasattr(cuckoo, "session"):
            return cuckoo.session
        sess = requests.Session()
        token = (getattr(self, 'api_token', '') or '').strip()
        if token:
            sess.headers.update({"Authorization": f"Token {token}"})
        if hasattr(self, 'verify_ssl'):
            sess.verify = bool(self.verify_ssl)
        return sess

    def _safe_get(self, func, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            self.log('warning', f'Error during request: {e}')
            return None

    # -------------------------------- hashes --------------------------------

    def _hash_file(self, path):
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}

    # -------------------------------- búsqueda por hash (apiv2 /tasks/search) --------------------------------

    def _search_task_by_hash(self, cuckoo, algo, digest):
        if not hasattr(cuckoo, "session") or not isinstance(digest, str) or not digest:
            return None
        path = f"tasks/search/{algo}/{digest}/"
        self._log_api('GET', path)
        try:
            r = cuckoo.session.get(self._full_url(path), timeout=20)
            r.raise_for_status()
            j = r.json()
            data = j.get("data", j) if isinstance(j, dict) else j
            if not isinstance(data, list):
                data = [data]
            cand = [t for t in data if isinstance(t, dict) and t.get("id")]
            tid = max(cand, key=lambda t: t["id"]).get("id") if cand else None
            self.log('info', f'Resultado búsqueda {algo}: task_id={tid}')
            return tid
        except Exception as e:
            self.log('warning', f'Búsqueda por hash falló ({algo}): {e}')
            return None

    def _find_existing_task(self, cuckoo, hashes):
        for algo in ("sha256", "sha1", "md5"):
            tid = self._search_task_by_hash(cuckoo, algo, hashes.get(algo))
            if tid:
                return tid
        return None

    # -------------------------------- estado / reporte --------------------------------

    def _task_status(self, cuckoo, task_id):
        path = f'tasks/view/{task_id}/'
        self._log_api('GET', path)
        view = self._safe_get(cuckoo.get_task_view, task_id) or {}
        data = view.get('data', {}) if isinstance(view, dict) else {}
        return data.get('status'), data

    def _get_task_report(self, cuckoo, task_id, report_format=None, make_zip=None):
        path = f"tasks/get/report/{task_id}/"
        if report_format:
            path += f"{report_format}/"
            if make_zip is not None:
                path += f"{make_zip}/"
        url = self._full_url(path)
        self.log('info', f'Descargando reporte JSON desde: {url}')
        self._log_api('GET', path)

        if hasattr(cuckoo, "session"):
            r = cuckoo.session.get(url, timeout=120)
            r.raise_for_status()
            if not report_format or report_format == "json":
                return r.json()
            return r.content
        return None

    # ---------- screenshots via ZIP (/apiv2/tasks/get/screenshot/<task_id>/) ----------

    def _fetch_screenshots_data_uris(self, cuckoo, task_id):
        """
        Descarga el ZIP de screenshots y devuelve una lista de data-URIs (strings).
        No expone ningún enlace de descarga.
        """
        path = f"tasks/get/screenshot/{task_id}/"
        url = self._full_url(path)
        self._log_api('GET', path)
        sess = self._get_session(cuckoo)
        try:
            r = sess.get(url, timeout=180)
            if r.status_code >= 400:
                preview = (r.text or '')[:200]
                self.log('warning', f'ZIP screenshots HTTP {r.status_code}: {preview}')
                return []
            r.raise_for_status()
        except Exception as e:
            self.log('warning', f'No se pudo descargar ZIP de screenshots: {e}')
            return []

        data = io.BytesIO(r.content)
        imgs = []
        try:
            with zipfile.ZipFile(data) as zf:
                names = [n for n in zf.namelist()
                         if n.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp'))]
                names.sort()
                for n in names:
                    blob = zf.read(n)
                    ext = n.split('.')[-1].lower()
                    mime = 'image/png' if ext == 'png' else ('image/jpeg' if ext in ('jpg', 'jpeg') else 'image/bmp')
                    b64 = base64.b64encode(blob).decode('ascii')
                    imgs.append(f"data:{mime};base64,{b64}")
        except Exception as e:
            self.log('warning', f'Error leyendo ZIP de screenshots: {e}')
            return []

        return imgs

    # -------------------------------- FAME hooks --------------------------------

    def is_ready_to_run(self, analysis):
        return True

    def get_report(self, target, sha256, file_type):
        cuckoo = self._make_client()

        # Asegura tener md5/sha1/sha256
        hashes = {"sha256": sha256, "sha1": None, "md5": None}
        if not isinstance(hashes["sha256"], str) or not hashes["sha256"]:
            try:
                calc = self._hash_file(target)
                hashes.update(calc)
                self.log('info', f'sha256 calculado para get_report: {hashes["sha256"]}')
            except Exception as e:
                self.log('warning', f'No se pudieron calcular hashes de {target}: {e}')

        # Buscar por hash
        self.log('info', 'Looking for previous reports on Sandbox')
        task_id = self._find_existing_task(cuckoo, hashes)

        new_submission = False

        # Subir si no existe
        if not task_id:
            # CAPE espera options como STRING (no dict)
            options_str = 'procmemdump=yes,route=none'
            data_common = {
                'priority': 3,
                'timeout': int(self.analysis_time),
                'enforce_timeout': 1,   # True/1
                'options': options_str,
            }

            # --- Intento 1: usar el wrapper si existe ---
            wrapper_ok = False
            try:
                if hasattr(cuckoo, 'create_file'):
                    # Muchos wrappers de Cuckoo/CAPE aceptan **kwargs con los campos de formulario.
                    resp = self._safe_get(
                        cuckoo.create_file,
                        os.path.basename(target),
                        target,
                        **data_common
                    ) or {}
                    # Normaliza los dos formatos posibles
                    if isinstance(resp, dict):
                        if 'task_id' in resp and resp.get('task_id'):
                            task_id = resp['task_id']
                            wrapper_ok = True
                        else:
                            task_id = (resp.get('data', {}) or {}).get('task_ids', [None])[0]
                            if task_id:
                                wrapper_ok = True
            except Exception as e:
                self.log('warning', f'Wrapper create_file falló: {e}')

            # --- Intento 2 (fallback): POST directo multipart a /tasks/create/file/ ---
            if not wrapper_ok or not task_id:
                try:
                    path_create = 'tasks/create/file/'
                    url_create = self._full_url(path_create)
                    self._log_api('POST', path_create, extra=f' (file={os.path.basename(target)})')

                    sess = self._get_session(cuckoo)

                    with open(target, 'rb') as f:
                        files = {'file': (os.path.basename(target), f)}
                        r = sess.post(url_create, data=data_common, files=files, timeout=600)
                        r.raise_for_status()
                        j = r.json() if r.headers.get('Content-Type', '').startswith('application/json') else {}
                        # Soporta ambos formatos
                        task_id = j.get('task_id') or (j.get('data', {}) or {}).get('task_ids', [None])[0]

                    if not task_id:
                        self.log('warning', f'Respuesta sin task_id al crear tarea: {j}')
                        return None

                    new_submission = True
                    self.log('info', f'Subido a CAPE correctamente: task_id={task_id}')

                except Exception as e:
                    self.log('warning', f'POST directo a CAPE falló: {e}')
                    return None
            else:
                new_submission = True


        # URL para UI
        self._last_task_id = task_id

        # Espera si la tarea está en curso (nueva o encontrada pero aún corriendo)
        status, _ = self._task_status(cuckoo, task_id)
        if status in ('pending', 'running', 'waiting'):
            first_wait = int(getattr(self, 'first_wait', 425)) if new_submission else 0
            self.log('info', f'Waiting for the analysis to be complete (primer chequeo en {first_wait} s)')
            if first_wait > 0:
                time.sleep(first_wait)

            try:
                def _logged_get_task_view(tid):
                    path = f'tasks/view/{tid}/'
                    self._log_api('GET', path)
                    return cuckoo.get_task_view(tid)
                self.wait_for_report(_logged_get_task_view, task_id, ['data', 'status'])
            except Exception as e:
                self.log('warning', f'La espera del reporte terminó con error/timeout: {e}')

        # Descargar JSON
        report = None
        try:
            report = self._get_task_report(cuckoo, task_id)
            if report:
                self.log('info', 'Downloading report from server')
                self.save_report(report, hashes.get("sha256"))
                self._extract_mitre(report)
            else:
                self.log('warning', f'Análisis no finalizado o sin reporte (status={status}). URL: {self.get_report_url(task_id, hashes.get("sha256"))}')
        except Exception as e:
            self.log('warning', f'No se pudo descargar/guardar el reporte: {e}')

        # --- Screenshots desde ZIP (sin exponer link) ---
        self._screenshots = []
        try:
            self._screenshots = self._fetch_screenshots_data_uris(cuckoo, task_id) or []
            self.log('info', f'screenshots detectados (ZIP): {len(self._screenshots)}')
        except Exception as e:
            self.log('warning', f'Error extrayendo screenshots: {e}')

        # --- Process tree ---
        self._process_tree = []
        try:
            beh = (report or {}).get("behavior", {}) or {}
            if isinstance(beh.get("processtree"), list):
                self._process_tree = beh["processtree"]
            else:
                procs = beh.get("processes") or []
                bypid = {}
                for p in procs:
                    if not isinstance(p, dict):
                        continue
                    node = {
                        "pid": p.get("pid"),
                        "name": p.get("process_name") or p.get("name"),
                        "cmdline": p.get("command_line") or p.get("cmdline"),
                        "children": []
                    }
                    bypid[p.get("pid")] = node
                for p in procs:
                    if not isinstance(p, dict):
                        continue
                    pid = p.get("pid")
                    ppid = p.get("parent_id") or p.get("ppid")
                    if pid in bypid and ppid in bypid:
                        bypid[ppid]["children"].append(bypid[pid])
                ppids = set()
                for p in procs:
                    pp = p.get("parent_id") or p.get("ppid")
                    if pp is not None:
                        ppids.add(pp)
                self._process_tree = [node for pid, node in bypid.items() if pid not in ppids]

            self.log('info', f'root processes: {len(self._process_tree)}')

            # Normaliza claves para la vista (image/name/cmdline/children)
            def _norm(node):
                if not isinstance(node, dict):
                    return node
                if not node.get("image"):
                    node["image"] = node.get("name") or node.get("process_name")
                if not node.get("name"):
                    node["name"] = node.get("image") or node.get("process_name")
                if not node.get("cmdline"):
                    node["cmdline"] = node.get("command_line")
                node["category"] = CTASCape._classify_process(
                    node.get("image") or node.get("name") or ''
                )
                children = node.get("children") or []
                node["children"] = [_norm(c) for c in children if isinstance(c, dict)]
                return node

            self._process_tree = [_norm(n) for n in (self._process_tree or [])]

        except Exception as e:
            self.log('warning', f'Error construyendo process tree: {e}')

        return task_id

    # -------------------------------- MITRE ATT&CK --------------------------------

    # Mapeo mínimo TID -> tácticas primarias para cuando el reporte no lo incluye.
    _TID_TACTICS = {
        'T1548': 'Privilege Escalation', 'T1134': 'Privilege Escalation',
        'T1547': 'Persistence',          'T1543': 'Persistence',
        'T1546': 'Persistence',          'T1574': 'Privilege Escalation',
        'T1055': 'Defense Evasion',      'T1027': 'Defense Evasion',
        'T1036': 'Defense Evasion',      'T1070': 'Defense Evasion',
        'T1112': 'Defense Evasion',      'T1140': 'Defense Evasion',
        'T1562': 'Defense Evasion',      'T1564': 'Defense Evasion',
        'T1059': 'Execution',            'T1106': 'Execution',
        'T1129': 'Execution',            'T1203': 'Execution',
        'T1204': 'Execution',            'T1053': 'Execution',
        'T1003': 'Credential Access',    'T1056': 'Credential Access',
        'T1110': 'Credential Access',    'T1555': 'Credential Access',
        'T1012': 'Discovery',            'T1018': 'Discovery',
        'T1057': 'Discovery',            'T1082': 'Discovery',
        'T1083': 'Discovery',            'T1518': 'Discovery',
        'T1016': 'Discovery',            'T1033': 'Discovery',
        'T1007': 'Discovery',            'T1069': 'Discovery',
        'T1087': 'Discovery',
        'T1071': 'Command and Control',  'T1095': 'Command and Control',
        'T1105': 'Command and Control',  'T1571': 'Command and Control',
        'T1572': 'Command and Control',  'T1573': 'Command and Control',
        'T1041': 'Exfiltration',         'T1048': 'Exfiltration',
        'T1486': 'Impact',               'T1489': 'Impact',
        'T1490': 'Impact',               'T1496': 'Impact',
        'T1113': 'Collection',           'T1115': 'Collection',
        'T1005': 'Collection',
        'T1566': 'Initial Access',       'T1190': 'Initial Access',
        'T1195': 'Initial Access',
        'T1588': 'Resource Development', 'T1583': 'Resource Development',
        'T1589': 'Reconnaissance',       'T1590': 'Reconnaissance',
    }

    @classmethod
    def _tid_to_tactic(cls, tid):
        """Devuelve la táctica primaria para un TID, o 'Execution' como fallback."""
        base = tid.split('.')[0] if tid else ''
        return cls._TID_TACTICS.get(base, 'Execution')

    def _extract_mitre(self, report):
        """Extrae TTPs del reporte CAPE y los registra en FAME via add_mitre_results."""
        if not report or not isinstance(report, dict):
            return

        ttp = {
            'Reconnaissance': {},       'Resource Development': {},
            'Initial Access': {},       'Execution': {},
            'Persistence': {},          'Privilege Escalation': {},
            'Defense Evasion': {},      'Credential Access': {},
            'Discovery': {},            'Lateral Movement': {},
            'Collection': {},           'Command and Control': {},
            'Exfiltration': {},         'Impact': {},
        }

        def _add(tactic, tid, name):
            if tactic in ttp and tid and name:
                ttp[tactic].setdefault(tid, name)

        # 1. Sección attack: {tactic: {tid: name}}  — formato más directo
        attack = report.get('attack') or {}
        if isinstance(attack, dict):
            for tactic, techniques in attack.items():
                if isinstance(techniques, dict):
                    for tid, name in techniques.items():
                        _add(tactic, tid, name)

        # 2. signatures[].ttp: {tid: {name, type, ...}}
        for sig in (report.get('signatures') or []):
            if not isinstance(sig, dict):
                continue
            for tid, info in (sig.get('ttp') or {}).items():
                if not isinstance(info, dict):
                    continue
                name = info.get('name') or tid
                # Buscar táctica en la sección attack ya procesada
                placed = any(
                    tid in ttp.get(tac, {})
                    for tac in ttp
                )
                if not placed:
                    # Buscar táctica en la sección attack del reporte
                    tactic = next(
                        (tac for tac, techs in attack.items()
                         if isinstance(techs, dict) and tid in techs),
                        self._tid_to_tactic(tid)
                    )
                    _add(tactic, tid, name)

        # 3. Lista top-level ttps: [{ttp/tid, name, tactic}, ...]
        for item in (report.get('ttps') or []):
            if not isinstance(item, dict):
                continue
            tid = item.get('ttp') or item.get('tid') or item.get('technique_id')
            name = item.get('name') or item.get('technique_name') or tid
            tactic = item.get('tactic') or item.get('tactic_name') or self._tid_to_tactic(tid)
            _add(tactic, tid, name)

        has_ttp = any(v for v in ttp.values())
        if has_ttp:
            self.log('info', f'MITRE TTPs encontrados: {sum(len(v) for v in ttp.values())} técnicas')
            # Convertir a formato [(tactic, {tid: name}), ...] compatible con el módulo Mitre
            self._mitre_tags = [[tac, techs] for tac, techs in ttp.items() if techs]
        else:
            self.log('info', 'MITRE: sin TTPs en el reporte de CAPE')
            self._mitre_tags = []

    def get_report_url(self, task_id, sha256, is_url=False):
        return urljoin(self.web_endpoint, f'analysis/{task_id}/')

    @staticmethod
    def _classify_process(name):
        import re
        n = (name or '').lower()
        b = n.replace('\\', '/').split('/')[-1].replace('.exe', '').replace('.com', '')

        if (len(b) > 28
                or re.match(r'^[0-9a-f]{8,}$', b)
                or re.match(r'^[a-z0-9]{20,}$', b)):
            return 'malware'
        if b in {'msbuild', 'csc', 'vbc', 'installutil', 'regasm', 'regsvcs', 'mshta',
                 'wscript', 'cscript', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin',
                 'wmic', 'msiexec', 'odbcconf', 'xwizard', 'mavinject', 'forfiles',
                 'pcalua', 'presentationhost', 'aspnet_compiler', 'ieexec',
                 'infdefaultinstall', 'cmstp', 'esentutl', 'expand', 'extrac32',
                 'findstr', 'gpscript', 'hh', 'makecab', 'replace', 'rpcping',
                 'scriptrunner', 'desktopimgdownldr', 'diskshadow', 'dnscmd',
                 'vssadmin', 'appsyncpublishingserver', 'microsoft.workflow.compiler'}:
            return 'lolbin'
        if b in {'powershell', 'powershell_ise', 'pwsh', 'cmd', 'bash', 'sh', 'wsh',
                 'autoit3', 'ahk', 'conhost'}:
            return 'script'
        if b in {'svchost', 'lsass', 'lsm', 'winlogon', 'csrss', 'smss', 'wininit',
                 'services', 'spoolsv', 'taskhost', 'taskhostw', 'dwm', 'fontdrvhost',
                 'ntoskrnl', 'system', 'registry', 'sihost', 'runtimebroker', 'ctfmon',
                 'dllhost', 'werfault', 'wmiprvse', 'audiodg', 'dashost', 'unsecapp',
                 'searchprotocolhost', 'searchfilterhost', 'dcomlaunch'}:
            return 'system'
        if b in {'explorer', 'taskmgr', 'regedit', 'mmc', 'control', 'mstsc',
                 'msconfig', 'resmon', 'perfmon'}:
            return 'shell'
        if (b in {'iexplore', 'chrome', 'firefox', 'msedge', 'edge', 'opera',
                  'brave', 'vivaldi', 'chromium'}
                or 'chrome' in b or 'firefox' in b or 'msedge' in b):
            return 'browser'
        if (b in {'winword', 'excel', 'powerpnt', 'outlook', 'onenote', 'mspub',
                  'visio', 'access', 'wordpad', 'acrord32', 'acrobat', 'foxitreader',
                  'soffice', 'officeclicktorun'}
                or 'word' in b or 'excel' in b or 'office' in b):
            return 'office'
        if b in {'devenv', 'code', 'node', 'python', 'python3', 'java', 'javaw',
                 'git', 'npm', 'dotnet', 'cargo', 'rustc', 'gcc', 'clang', 'ruby',
                 'perl', 'php', 'go', 'gradle', 'mvn'}:
            return 'dev'
        if (b in {'mousocoreworker', 'tiworker', 'wuauclt', 'trustedinstaller',
                  'mpcmdrun', 'msmpeng', 'nissrv', 'searchindexer', 'schtasks',
                  'taskeng', 'mobsync', 'uhssvc', 'wudfhost'}
                or 'update' in b or 'install' in b or 'setup' in b):
            return 'worker'
        if b in {'netsh', 'ipconfig', 'ping', 'nslookup', 'ftp', 'ssh', 'curl',
                 'wget', 'nc', 'nmap', 'tracert', 'route', 'arp', 'hostname',
                 'whoami', 'net', 'nltest', 'dsquery'}:
            return 'network'
        return 'generic'

    # -------------------- Resultados para la vista --------------------

    def custom_logic(self):
        # Familia desde detections
        family = ''
        try:
            det = self.resolve_single_data('detections') or []
            if isinstance(det, list) and det:
                fam = det[0]
                if isinstance(fam, dict):
                    family = str(fam.get('family') or '').strip()
                elif isinstance(fam, str):
                    family = fam.strip()
        except Exception:
            pass

        # Score (0..10 -> 0..100)
        score10 = 0.0
        try:
            v = self.resolve_single_data('malscore')
            v = v[0] if isinstance(v, list) and v else v
            score10 = float(v) if v is not None else 0.0
        except Exception:
            score10 = 0.0
        score = max(0.0, min(100.0, score10 * 10.0))

        # Signatures
        try:
            raw_sigs = self.resolve_single_data('signatures.item') or []
        except Exception:
            raw_sigs = []
        if not isinstance(raw_sigs, list):
            raw_sigs = [raw_sigs]

        signatures = []
        for it in raw_sigs:
            if isinstance(it, dict):
                desc = (it.get('description') or it.get('name') or str(it)).strip()
                sev_raw = it.get('severity', 0)
            else:
                desc = str(it)
                sev_raw = 0
            try:
                sev = int(sev_raw)
                if 0 <= sev <= 5:
                    sev = sev * 20
            except Exception:
                sev = 0
            signatures.append({"severity": sev, "description": desc})

        # URL web
        tid = getattr(self, "_last_task_id", None)
        analysis_url = self.get_report_url(tid, None) if tid else ""

        # Adjuntar screenshots, árbol y MITRE tags
        screenshots = getattr(self, "_screenshots", []) or []
        process_tree = getattr(self, "_process_tree", []) or []
        mitre_tags = getattr(self, "_mitre_tags", []) or []

        # Sugerir nombre si el score es 100
        if score >= 100 and family:
            try:
                self.add_probable_name(family)
            except Exception:
                pass

        return [
            ('mal_family', family),
            ('score', score),
            ('signatures', signatures),
            ('analysis_url', analysis_url),
            ('screenshots', screenshots),     # data-URIs list
            ('process_tree', process_tree),    # clave "nueva"
            ('proctree', process_tree),        # alias para plantillas existentes
            ('mitre_tags', mitre_tags),        # para el módulo Mitre: [[tactic, {tid: name}], ...]
        ]
