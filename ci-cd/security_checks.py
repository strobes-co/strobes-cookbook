import sys
import os
from strobes_gql_client.client import StrobesGQLClient

# Initialize Strobes client
strobes_client = StrobesGQLClient(
    host="demovm.strobes.co",
    api_token="your_strobes_api_token_here"
)

# Configuration
ORGANIZATION_ID = "your_strobes_organization_id_here"
REPO_NAME = os.environ.get('CI_PROJECT_NAME', 'Unknown Project')
BUG_THRESHOLD = int(os.environ.get('BUG_THRESHOLD', 5)
                    )  # Default to 5 if not set


def get_bugs_for_repo(repo_name):
    """
    Query Strobes for bugs associated with the given repository name
    """
    bugs = []
    page = 1
    while True:
        result = strobes_client.execute_query(
            'all_bugs',
            organization_id=ORGANIZATION_ID,
            search_query=f'tags:"{repo_name}"',
            page=page,
            page_size=100
        )
        bugs.extend(result['objects'])
        if not result['hasNext']:
            break
        page += 1
    return bugs


def count_open_bugs(bugs):
    """
    Count the number of open bugs
    """
    return sum(1 for bug in bugs if bug['state'] in [0, 1, 2])  # Assuming 0, 1, 2 are open states


def print_bug_summary(bugs):
    """
    Print a summary of the bugs found
    """
    open_bugs = [bug for bug in bugs if bug['state'] in [0, 1, 2]]
    print(f"Total bugs found: {len(bugs)}")
    print(f"Open bugs: {len(open_bugs)}")
    print("\nOpen bug summary:")
    for bug in open_bugs:
        print(f"- [{bug['severity']}] {bug['title']} (ID: {bug['id']})")


def main():
    print(f"Checking bugs for repository: {REPO_NAME}")
    print(f"Bug threshold: {BUG_THRESHOLD}")

    bugs = get_bugs_for_repo(REPO_NAME)
    open_bug_count = count_open_bugs(bugs)

    print_bug_summary(bugs)

    if open_bug_count > BUG_THRESHOLD:
        print(f"\nError: Number of open bugs ({
              open_bug_count}) exceeds the threshold ({BUG_THRESHOLD}).")
        print("CI process will be terminated.")
        sys.exit(1)
    else:
        print(f"\nSuccess: Number of open bugs ({
              open_bug_count}) is within the acceptable range.")
        print("CI process can continue.")
        sys.exit(0)


if __name__ == "__main__":
    main()
