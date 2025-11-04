class Reloader:
    def __init__(self, service_name='haproxy'):
        self.service_name = service_name

    def restart_service(self):
        import subprocess
        try:
            subprocess.run(['systemctl', 'restart', self.service_name], check=True)
            print(f"{self.service_name} service restarted successfully.")
        except subprocess.CalledProcessError as e:
            print(f"Failed to restart {self.service_name} service: {e}")

    def check_service_status(self):
        import subprocess
        try:
            result = subprocess.run(['systemctl', 'is-active', self.service_name], capture_output=True, text=True, check=True)
            return result.stdout.strip() == 'active'
        except subprocess.CalledProcessError:
            return False