class Manager:
    def __init__(self, config_parser):
        self.config_parser = config_parser

    def edit_backend(self, backend_name, new_settings):
        # Logic to edit the backend settings in the configuration
        backend = self.config_parser.get_backend(backend_name)
        if backend:
            backend.update(new_settings)
            self.save_changes()
            return True
        return False

    def restart_backend(self, backend_name):
        # Logic to restart the specified backend
        if self.config_parser.backend_exists(backend_name):
            self._restart_haproxy()
            return True
        return False

    def save_changes(self):
        # Logic to save changes to the HAProxy configuration file
        with open(self.config_parser.config_file_path, 'w') as config_file:
            config_file.write(self.config_parser.generate_config())

    def _restart_haproxy(self):
        # Logic to restart the HAProxy service
        import subprocess
        subprocess.run(['systemctl', 'restart', 'haproxy'], check=True)