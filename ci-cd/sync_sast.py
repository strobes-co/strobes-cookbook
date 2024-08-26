import sys
import os
import subprocess
import json
from strobes_gql_client.client import StrobesGQLClient

# Initialize Strobes client
strobes_client = StrobesGQLClient(
    host="demovm.strobes.co",
    api_token="your_strobes_api_token_here"
)

ORGANIZATION_ID = "your_strobes_organization_id_here"
PROJECT_NAME = os.environ.get('CI_PROJECT_NAME', 'Unknown Project')
COMMIT_HASH = os.environ.get('CI_COMMIT_SHA', 'Unknown Commit')


def run_command(command):
    """Run a shell command and return its output"""
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()
    return stdout.decode('utf-8'), stderr.decode('utf-8'), process.returncode


def run_sast_scan():
    """Run a Static Application Security Testing (SAST) scan"""
    print("Running SAST scan...")
    # This is a placeholder. Replace with your actual SAST tool command.
    stdout, stderr, exit_code = run_command(
        "semgrep --config=p/owasp-top-ten --json .")
    if exit_code != 0:
        print(f"SAST scan failed: {stderr}")
        return []
    return json.loads(stdout)


def run_dependency_check():
    """Run a dependency check for vulnerabilities"""
    print("Running dependency check...")
    # This is a placeholder. Replace with your actual dependency check tool command.
    stdout, stderr, exit_code = run_command("safety check --json")
    if exit_code != 0:
        print(f"Dependency check failed: {stderr}")
        return []
    return json.loads(stdout)


def create_strobes_bug(title, description, severity):
    """Create a bug in Strobes"""
    bug_data = {
        "title": title,
        "description": description,
        "organization_id": ORGANIZATION_ID,
        "bug_level": 1,  # Assuming 1 is for code-level vulnerabilities
        "severity": severity,
        "tags": ["CI/CD", PROJECT_NAME, COMMIT_HASH],
    }
    result = strobes_client.execute_mutation('bug_create', **bug_data)
    return result['bug']['id']


def process_sast_results(results):
    """Process SAST results and create bugs in Strobes"""
    for result in results:
        title = f"SAST: {result['check_id']} in {result['path']}"
        description = f"""
        SAST vulnerability found:
        File: {result['path']}
        Line: {result['start']['line']}
        Message: {result['extra']['message']}

        Code:
        ```
        {result['extra']['lines']}
        ```
        """
        severity = 4 if result['extra']['severity'] == 'ERROR' else 3  # Map severity to Strobes scale
        bug_id = create_strobes_bug(title, description, severity)
        print(f"Created Strobes bug {bug_id} for SAST finding: {title}")


def process_dependency_results(results):
    """Process dependency check results and create bugs in Strobes"""
    for result in results:
        title = f"Vulnerable Dependency: {
            result['package']} {result['installed_version']}"
        description = f"""
        Vulnerable dependency found:
        Package: {result['package']}
        Installed Version: {result['installed_version']}
        Vulnerability: {result['vulnerability']}

        Advisory: {result['advisory']}
        """
        severity = 4 if result['severity'] == 'high' else 3  # Map severity to Strobes scale
        bug_id = create_strobes_bug(title, description, severity)
        print(f"Created Strobes bug {
              bug_id} for vulnerable dependency: {title}")


def main():
    sast_results = run_sast_scan()
    dependency_results = run_dependency_check()

    total_issues = len(sast_results) + len(dependency_results)

    if total_issues > 0:
        print(
            f"Found {total_issues} security issues. Creating bugs in Strobes...")
        process_sast_results(sast_results)
        process_dependency_results(dependency_results)
        print(f"Created {total_issues} bugs in Strobes.")
        print("Security checks failed. Please review and address the issues in Strobes.")
        sys.exit(1)
    else:
        print("No security issues found. Pipeline check passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
