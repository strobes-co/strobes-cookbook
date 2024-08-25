"""
This script synchronizes EC2 instances to Strobes using a GraphQL API client. It fetches information about EC2 instances from AWS, formats it into a specific asset data structure, and sends this data to the Strobes platform via GraphQL mutation.
"""

import boto3  # Import the Boto3 library for interacting with AWS services
# Import the Strobes GQL client for making GraphQL requests
from strobes_gql_client.client import StrobesGQLClient

# Initialize the Strobes GQL client with the provided host and API token
client = StrobesGQLClient(
    host="x.strobes.co",
    api_token="xx"
)


def sync_ec2_to_strobes():
    """
    Fetches EC2 instances, formats them into asset data, and sends the data to Strobes via GraphQL mutation.
    """
    ec2 = boto3.client('ec2')  # Create a Boto3 client for EC2

    response = ec2.describe_instances()  # Describe all instances in the AWS account
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            asset_data = {
                # The name of the EC2 instance is its ID
                "name": instance['InstanceId'],
                "organization_id": "xx",  # Placeholder organization ID
                "sensitivity": 4,  # Sensitivity level (example value)
                # Determine if the instance is exposed based on its state
                "exposed": 1 if instance['State']['Name'] != 'terminated' else 0,
                "type": 3,  # Type of asset (example value)
                # Determine the OS based on the platform details or default to Linux if not specified
                "os": instance.get('PlatformDetails', 'Linux') if instance.get('PlatformDetails') else 'Linux',
                # Use private or public DNS name as hostname
                "hostname": instance['PrivateDnsName'] or instance['PublicDnsName'],
                # Extract MAC address of the first network interface
                "mac_address": instance['NetworkInterfaces'][0]['MacAddress'] if instance['NetworkInterfaces'] else None,
                # Use private or public IP address as IP address
                "ipaddress": instance['PrivateIpAddress'] or instance['PublicIpAddress'],
            }

            # Send the asset data to Strobes via GraphQL mutation
            client.execute_mutation('create_asset', **asset_data)


if __name__ == "__main__":
    # Run the synchronization function when the script is executed directly
    sync_ec2_to_strobes()
