class Config:
    DEFAULT_HAPROXY_CONFIG_PATH = '/etc/haproxy/haproxy.cfg'
    BACKEND_SECTION_PREFIX = 'backend'
    TIMEOUT_DEFAULT = '5000ms'
    MAX_CONNECTIONS = 2000

    @staticmethod
    def get_default_config_path():
        return Config.DEFAULT_HAPROXY_CONFIG_PATH

    @staticmethod
    def get_backend_section_prefix():
        return Config.BACKEND_SECTION_PREFIX

    @staticmethod
    def get_timeout_default():
        return Config.TIMEOUT_DEFAULT

    @staticmethod
    def get_max_connections():
        return Config.MAX_CONNECTIONS