import os
from urllib.parse import urljoin

from fame.common.exceptions import ModuleInitializationError
from fame.core.module import APIProcessingModule
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
        {
            'name': 'api_endpoint',
            'type': 'str',
            'default': 'https://mal-prod-cape.immunityinc.com/api/',
            'description': 'URL of CAPE\'s API endpoint.'
        },
        {
            'name': 'web_endpoint',
            'type': 'str',
            'default': 'https://mal-prod-cape.immunityinc.com/',
            'description': 'URL of CAPE\'s web interface.'
        },
        {
            'name': 'wait_timeout',
            'type': 'integer',
            'default': 5400,
            'description': 'Time in seconds that the module will wait for the analysis to be over.'
        },
        {
            'name': 'wait_step',
            'type': 'integer',
            'default': 30,
            'description': 'Time in seconds between two check of CAPE\'s analysis status'
        },
        {
            'name': 'analysis_time',
            'type': 'integer',
            'default': 300,
            'description': 'Time (in seconds) during which the sample will be analyzed.',
        }
    ]

    permissions = {
        'cape_access': 'For users that have access to the Cuckoo Sandbox instance. Will display a link to the analysis.'
    }

    parse_format = {
        'iocs': {
            'association': {
                'URL': ['target.file.urls.item']
            },
            'behaviour': {
                'URL': [
                    'network.http.item.uri', 'metadata.cfgextr.item.url.item'
                ],
                'Mutex': ['behavior.summary.mutexes.item'],
                'Registry Key': ['behavior.summary.write_keys.item'],
                'Address': ['network.udp.item.dst', 'network.tcp.item.dst'],
                'Host': ['network.domains.item.domain'],
            }
        },
        'attributes': {
            # General attributes
            'sha512': 'target.file.sha512',

            # PE related attributes
            'pe.debug_symbol_path': 'static.pe.pdbpath',
            'pe.import_hash': 'static.pe.imphash',
            'pe.timestamp': 'static.pe.timestamp'
        }
    }

    def initialize(self):
        if not HAS_CUCKOO:
            raise ModuleInitializationError(self, 'Missing dependency: cuckoo_api_handler')

    def is_ready_to_run(self, analysis):
        cuckoo = Cuckoo(self.api_endpoint, cape=True)
        sha256 = analysis._file["sha256"]
        target = analysis._file['filepath']

        self.log('info', 'Looking for previous reports on Sandbox')
        task_id = None

        for task in reversed(cuckoo.get_task_list()['data']):
            if 'sha256' in task['sample'] and task['sample']['sha256'] == sha256:
                task_id = task['id']

        if not task_id:
            options = {
                'priority': 3,
                'timeout': self.analysis_time,
                'enforce_timeout': True,
                'options': {'route=none'}
            }

            self.log('info', 'File was not found; now sending sample to Cuckoo')
            response = cuckoo.create_file(os.path.basename(target), target, **options)

            if 'error' in response and response['error']:
                self.log('warning', 'CAPE returned an error: {}'.format(response))
                return False

            task_id = response['data']['task_ids'][0]

        status = cuckoo.get_task_view(task_id)['data']['status']
        return status not in ('pending', 'running', 'waiting')

    def get_report(self, target, sha256, file_type):
        cuckoo = Cuckoo(self.api_endpoint, cape=True)

        self.log('info', 'Looking for previous reports on Sandbox')
        task_id = None

        for task in cuckoo.get_task_list()['data']:
            if 'sha256' in task['sample'] and task['sample']['sha256'] == sha256:
                task_id = task['id']
                break

        if not task_id:
            options = {
                'priority': 3,
                'timeout': self.analysis_time,
                'enforce_timeout': True,
                'options': {'procmemdump=yes,route=none'}
            }

            self.log('info', 'File was not found; now sending sample to CAPE')
            response = cuckoo.create_file(os.path.basename(target), target, **options)

            if 'error' in response and response['error']:
                self.log('warning', 'CAPE returned an error: {}'.format(response))
                return None

            task_id = response['data']['task_ids'][0]

            self.log('info', 'Waiting for the analysis to be complete')
            self.wait_for_report(cuckoo.get_task_view, task_id, ['data', 'status'])

        self.log('info', 'Downloading report from server')
        self.save_report(cuckoo.get_task_report(task_id), sha256)
        return task_id

    def get_report_url(self, task_id, sha256, is_url=False):
        return urljoin(self.web_endpoint, 'analysis/{}/'.format(task_id))

    def custom_logic(self):
        mal_family = None
        detections = self.resolve_single_data('detections')
        if detections:
            mal_family = detections[0]

        malscore_data = self.resolve_single_data('malscore')
        score = float(malscore_data[0]) * 10 if malscore_data else 0.0

        if score == 100 and mal_family:
            self.add_probable_name(mal_family)

        signatures_data = self.resolve_single_data('signatures.item')
        signatures = [{'severity': item['severity'] * 20, 'description': item['description']}
                      for item in (signatures_data or [])]

        task_id_data = self.resolve_single_data('info.id')
        task_id = task_id_data[0] if task_id_data else None
        analysis_url = self.get_report_url(task_id, None) if task_id else None

        return [('mal_family', mal_family), ('score', score), ('signatures', signatures),
                ('analysis_url', analysis_url)]
