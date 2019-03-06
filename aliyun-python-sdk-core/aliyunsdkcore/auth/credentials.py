import os
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.vendored import six


# credentials
class AccessKeyCredential:
    def __init__(self, access_key_id, access_key_secret):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret


class StsTokenCredential:
    def __init__(self, sts_access_key_id, sts_access_key_secret, sts_token):
        self.sts_access_key_id = sts_access_key_id
        self.sts_access_key_secret = sts_access_key_secret
        self.sts_token = sts_token


class RamRoleArnCredential:
    def __init__(self, sts_access_key_id, sts_access_key_secret, role_arn, session_role_name):
        self.sts_access_key_id = sts_access_key_id
        self.sts_access_key_secret = sts_access_key_secret
        self.role_arn = role_arn
        self.session_role_name = session_role_name


class EcsRamRoleCredential:
    def __init__(self, role_name):
        self.role_name = role_name


class BearTokenCredential:
    def __init__(self, bearer_token):
        self.bearer_token = bearer_token


class RsaKeyPairCredential:
    def __init__(self, public_key_id, private_key, session_period=3600):
        self.public_key_id = public_key_id
        self.private_key = private_key
        self.session_period = session_period


# parse ini file
def _parse_nested(config_value):
    parsed = {}
    for line in config_value.splitlines():
        line = line.strip()
        if not line:
            continue
        key, value = line.split('=', 1)
        parsed[key.strip()] = value.strip()
    return parsed


def raw_config_parse(config_filename, parse_subsections=True):
    config = {}
    path = config_filename
    if path is not None:
        path = os.path.expandvars(path)
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            raise ClientException(
                'CredentialFileNotFound',
                'The specified credentials file (%s) does not exist.' % path,
            )
        cp = six.moves.configparser.RawConfigParser()
        try:
            cp.read([path])
        except six.moves.configparser.ParsingError:
            raise ClientException(
                'ConfigParseError',
                'credentials file (%s) format is incorrect' % path
            )
        except six.moves.configparser.Error:
            raise ClientException(
                'ConfigReadError',
                ' Credential file  (%s) is not readable' % path
            )
        else:
            for section in cp.sections():
                config[section] = {}
                for option in cp.options(section):
                    config_value = cp.get(section, option)
                    if parse_subsections and config_value.startswith('\n'):
                        try:
                            config_value = _parse_nested(config_value)
                        except ValueError:
                            raise ClientException(
                                'ConfigParseError',
                                'Unable to parse config file: %s' % path
                            )
                    config[section][option] = config_value
    return config


def load_config(config_filename):
    parsed = raw_config_parse(config_filename)
    return parsed

# load config


class DefaultCredentialsProvider(object):
    def __init__(self, credential):
        profile_name = credential.get('profile_name') or 'default'
        providers = [
            UserProvider(credential),
            EnvProvider(),
            ProfileCredentialsProvider(profile_name=profile_name),
            InstanceCredentialsProvider(),
        ]
        self.providers = providers

    def load_credentials(self):
        for provider in self.providers:
            creds = provider.load()
            if creds is not None:
                return creds
        return None


class CredentialProvider(object):

    def load(self):
        return True


class UserProvider(CredentialProvider):
    def __init__(self, credential):
        self.credentials = credential

    def load(self):
        if self.credentials:
            fetcher = self._create_credentials_fetcher()
            credentials = fetcher()
            return credentials
        else:
            return None

    def _create_credentials_fetcher(self):
        credentials = self.credentials

        def fetch_credentials():
            access_key_id = credentials.get('access_key_id')
            public_key_id = credentials.get('public_key_id')
            credential = credentials.get('credential')
            if access_key_id is not None:
                access_key_secret = credentials.get('access_key_secret')
                if access_key_secret is None:
                    raise ClientException(
                        'credentials error',
                        'Partial credentials found in env, missing: access_key_secret')
                return AccessKeyCredential(
                    access_key_id=access_key_id,
                    access_key_secret=access_key_secret)
            elif public_key_id is not None:
                private_key = credentials.get('private_key')
                if private_key is None:
                    raise ClientException(
                        'credentials error',
                        'Partial credentials found in env, missing: access_key_secret')
                session_period = credentials.get('session_period')
                if session_period is None:
                    raise ClientException(
                        'credentials error',
                        'Partial credentials found in env, missing: access_key_secret')
                return RsaKeyPairCredential(
                    public_key_id=public_key_id,
                    private_key=private_key)
            elif credential is not None:
                return credential
            else:
                return None

        return fetch_credentials


class EnvProvider(CredentialProvider):
    ACCESS_KEY_ID = 'ALIBABA_CLOUD_ACCESS_KEY_ID'
    ACCESS_KEY_SECRET = 'ALIBABA_CLOUD_ACCESS_KEY_SECRET'

    def __init__(self, environ=None):
        if environ is None:
            environ = os.environ
        self.environ = environ

    def load(self):

        if self.ACCESS_KEY_ID in self.environ:
            fetcher = self._create_credentials_fetcher()
            credentials = fetcher()
            return credentials
        else:
            return None

    def _create_credentials_fetcher(self):
        environ = self.environ

        def fetch_credentials():
            access_key_id = environ.get(self.ACCESS_KEY_ID)
            if access_key_id is None:
                raise ClientException(
                    'credentials error',
                    'Environment variable access_key_id cannot be empty')
            access_key_secret = environ.get(self.ACCESS_KEY_SECRET)
            if access_key_secret is None:
                raise ClientException(
                    'credentials error',
                    'Environment variable access_key_secret cannot be empty')

            credential = AccessKeyCredential(
                access_key_id=access_key_id,
                access_key_secret=access_key_secret)
            return credential

        return fetch_credentials


class ProfileResolve:
    def __init__(self, profile):
        self.profile = profile

    def resolve_type_of_access_key(self):
        access_key_id = self.profile.get('access_key_id')
        access_key_secret = self.profile.get('access_key_secret')
        return AccessKeyCredential(access_key_id, access_key_secret)

    def resolve_type_of_ecs_ram_role(self):
        role_name = self.profile.get('role_name')
        return EcsRamRoleCredential(role_name)

    def resolve_type_of_ram_role_arn(self):
        access_key_id = self.profile.get('access_key_id')
        access_key_secret = self.profile.get('access_key_secret')
        role_arn = self.profile.get('role_arn')
        session_name = self.profile.get('session_name')
        return RamRoleArnCredential(
            access_key_id,
            access_key_secret,
            role_arn,
            session_name
        )

    def resolve_type_of_bearer_token(self):
        bearer_token = self.profile.get('bearer_token')
        return BearTokenCredential(bearer_token)

    def resolve_type_of_rsa_key_pair(self):
        public_key_id = self.profile.get('public_key_id')
        private_key_file = self.profile.get('private_key_file')
        session_period = self.profile.get('session_period')
        return RsaKeyPairCredential(public_key_id, private_key_file, session_period)

    def resolve_type_of_sts_token(self):
        access_key_id = self.profile.get('access_key_id')
        access_key_secret = self.profile.get('access_key_secret')
        sts_token = self.profile.get('sts_token')
        return StsTokenCredential(access_key_id, access_key_secret, sts_token)


class ProfileCredentialsProvider(CredentialProvider):
    CRED_FILE_ENV = 'ALIBABA_CLOUD_CREDENTIALS_FILE'
    DEFAULT_CONFIG_FILENAMES = ['/etc/.alibabacloud/credentials', '~/.alibabacloud/credentials']

    def __init__(self, profile_name=None):
        self._profile_name = profile_name
        self._environ = os.environ

    def load(self):
        self._loaded_config = {}

        if 'ALIBABA_CLOUD_CREDENTIALS_FILE' in self._environ:
            if self._environ.get('ALIBABA_CLOUD_CREDENTIALS_FILE') is None:
                raise ClientException(
                    'credentials filepath error',
                    'The specified credential file path is invalid'
                )
            full_path = os.path.expanduser(
                self._environ['ALIBABA_CLOUD_CREDENTIALS_FILE'])
            self._loaded_config = load_config(full_path)
        else:
            potential_locations = self.DEFAULT_CONFIG_FILENAMES
            for filename in potential_locations:
                try:
                    self._loaded_config = load_config(filename)
                    break
                except Exception:
                    continue
        profile = self._loaded_config.get(self._profile_name, {})

        if 'type' in profile:
            return self._load_creds_from_ini_type(profile)
        return None

    def _load_creds_from_ini_type(self, profile):

        profile_type = profile.get('type')
        resolve_profile = ProfileResolve(profile=profile)

        credential_map = {
            'access_key': resolve_profile.resolve_type_of_access_key,
            'ecs_ram_role': resolve_profile.resolve_type_of_ecs_ram_role,
            'ram_role_arn': resolve_profile.resolve_type_of_ram_role_arn,
            'bearer_token': resolve_profile.resolve_type_of_bearer_token,
            'rsa_key_pair': resolve_profile.resolve_type_of_rsa_key_pair,
            'sts_token': resolve_profile.resolve_type_of_sts_token,
        }
        get_credential = credential_map[profile_type]
        credentials = get_credential()
        return credentials


class InstanceCredentialsProvider(CredentialProvider):
    CRED_ECS_ENV = 'ALIBABA_CLOUD_ECS_METADATA'

    def __init__(self):
        self._environ = os.environ

    def load(self):
        if self.CRED_ECS_ENV in self._environ:
            if self._environ['ALIBABA_CLOUD_ECS_METADATA'] is None:
                raise ClientException(
                    'ALIBABA_CLOUD_ECS_METADATA',
                    'ALIBABA_CLOUD_ECS_METADATA is None'
                )
            role_name = self._environ['ALIBABA_CLOUD_ECS_METADATA']
            credentials = EcsRamRoleCredential(role_name)
            return credentials
        else:
            return None
