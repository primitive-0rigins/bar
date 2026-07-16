import subprocess

STATES = ["queued", "running", "complete"]

class Runner:
    def run(self, command):
        subprocess.run(command)
        self.publish("complete")

def test_runner_runs_command():
    runner = Runner()
    runner.run(["true"])
