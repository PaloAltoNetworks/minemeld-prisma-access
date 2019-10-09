import logging
import os

import yaml
import requests
from netaddr import IPAddress

from minemeld.ft.basepoller import BasePollerFT
from minemeld.ft.utils import interval_in_sec


LOG = logging.getLogger(__name__)


PRISMA_ACCESS_API_QUERY = 'https://api.gpcloudservice.com/getAddrList/latest?fwType=gpcs_remote_network&addrType=public_ip'

class Miner(BasePollerFT):
    def configure(self):
        super(Miner, self).configure()

        self.verify_cert = self.config.get('verify_cert', True)
        self.polling_timeout = self.config.get('polling_timeout', 20)

        self.api_keys = []
        self.side_config_path = os.path.join(
            os.environ['MM_CONFIG_DIR'],
            '%s_side_config.yml' % self.name
        )

        self._load_side_config()

    def _load_side_config(self):
        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading side config: %s', self.name, str(e))
            return

        api_keys = sconfig.get('api_keys', None)
        if api_keys is not None and isinstance(api_keys, list):
            self.api_keys = api_keys
            LOG.info('{} - Loaded API keys from side config'.format(self.name))

        verify_cert = sconfig.get('verify_cert', None)
        if verify_cert is not None:
            self.verify_cert = verify_cert
            LOG.info('{} - Loaded verify cert from side config'.format(self.name))

    def _process_item(self, item):
        indicator = item.pop('indicator', None)
        if indicator is None:
            return []

        return [[indicator, item]]

    def _query_api(self, api_key):
        LOG.debug('{} - requesting address list for {}'.format(self.name, api_key))
        url = PRISMA_ACCESS_API_QUERY

        headers = {
            'header-api-key': api_key
        }

        rkwargs = dict(
            stream=False,
            verify=self.verify_cert,
            timeout=self.polling_timeout,
            headers=headers
        )

        r = requests.get(
            url,
            **rkwargs
        )

        try:
            r.raise_for_status()
        except Exception:
            LOG.debug(
                '{} - exception in request: {!r} {!r}'.format(self.name, r.status_code, r.content)
            )
            raise

        result = r.json()

        if 'status' not in result or result['status'] != 'success':
            raise RuntimeError('{} - invalid format returned'.format(self.name))

        result = result.get('result', None)
        if result is None:
            raise RuntimeError('{} - invalid format returned'.format(self.name))

        addr_list = result.get('addrList', None)
        if addr_list is None or not isinstance(addr_list, list):
            raise RuntimeError('{} - invalid format returned'.format(self.name))

        return addr_list

    def _api_keys_iterator(self):
        addresses = set()

        for api_key in self.api_keys:
            try:
                for address in self._query_api(api_key):
                    if isinstance(address, str) or isinstance(address, unicode):
                        _, real_address = address.split(':', 1)
                    elif isinstance(addresses, dict):
                        address = address["address"]
                    else:
                        raise RuntimeError('{} - Unknown address type: {!r}'.format(self.name, address))

                    addresses.add(real_address)

            except Exception:
                LOG.exception('{} - Error handling: {!r}'.format(self.name, api_key))
                raise

        for address in addresses:
            try:
                na = IPAddress(address)
                if na.version == 4:
                    yield dict(indicator=address, type='IPv4')
                elif na.version == 6:
                    yield dict(indicator=address, type='IPv6')
                else:
                    LOG.error('{} - Unknown IP address type: {!r}'.format(self.name, address))

            except Exception:
                LOG.exception('{} - Error handling: {!r}'.format(self.name, address))
                raise

    def _build_iterator(self, now):
        if self.api_keys is None or len(self.api_keys) == 0:
            raise RuntimeError('API Keys not set, poll not performed')

        return self._api_keys_iterator()

    def hup(self, source=None):
        LOG.info('%s - hup received, reload side config', self.name)
        self._load_side_config()
        super(Miner, self).hup(source)

    @staticmethod
    def gc(name, config=None):
        BasePollerFT.gc(name, config=config)

        side_config_path = None
        if config is not None:
            side_config_path = config.get('side_config', None)
        if side_config_path is None:
            side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '{}_side_config.yml'.format(name)
            )

        try:
            os.remove(side_config_path)
        except Exception:
            pass
