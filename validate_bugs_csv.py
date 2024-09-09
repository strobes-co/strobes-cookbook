import csv
import unicodedata
import re
import chardet
from typing import Dict, List, Tuple
from enum import IntEnum


class BugLevel(IntEnum):
    CODE = 1
    WEB = 2
    NETWORK = 4
    CLOUD = 5
    PACKAGE = 6


class CloudType(IntEnum):
    OTHERS = 1
    AWS = 2
    AZURE = 3
    GCP = 4


class BugsValidator:
    cloud_options = {
        'aws_regions': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-south-1'],
        'azure_regions': ['eastus', 'westus', 'northeurope', 'westcentralus'],
        'gcp_regions': ['us-central1', 'us-east1', 'europe-west1', 'asia-east1'],
        'services': ['ec2', 's3', 'rds', 'elb']
    }

    @classmethod
    def is_valid_bug_data(cls, bug_data: Dict) -> bool:
        cls.has_valid_common_fields(bug_data)

        bug_level = int(bug_data.get('bug_level', 0))
        if bug_level not in [level.value for level in BugLevel]:
            raise ValueError(f"Invalid bug level: {bug_level}. Expected one of {
                             [level.value for level in BugLevel]}")

        if bug_level == BugLevel.CODE:
            cls.is_valid_code_bug(bug_data)
        elif bug_level == BugLevel.WEB:
            cls.is_valid_web_bug(bug_data)
        elif bug_level == BugLevel.NETWORK:
            cls.is_valid_network_bug(bug_data)
        elif bug_level == BugLevel.PACKAGE:
            cls.is_valid_package_bug(bug_data)
        elif bug_level == BugLevel.CLOUD:
            cls.is_valid_cloud_bug(bug_data)

        return True

    @staticmethod
    def has_valid_common_fields(bug_data: Dict) -> bool:
        required_fields = ['title', 'description', 'mitigation']
        missing_fields = [
            field for field in required_fields if not bug_data.get(field)]
        if missing_fields:
            raise ValueError(f"Missing required common field(s): {', '.join(
                missing_fields)}. All bugs must have a title, description, and mitigation.")
        return True

    @staticmethod
    def is_valid_code_bug(bug_data: Dict) -> bool:
        required_fields = ['vulnerable_code', 'file_name',
                           'start_line_number', 'end_line_number']
        missing_fields = [
            field for field in required_fields if not bug_data.get(field)]
        if missing_fields:
            raise ValueError(f"Missing required field(s) for code bug (bug_level 1): {', '.join(
                missing_fields)}. Code bugs must specify the vulnerable code, file name, and line numbers.")
        return True

    @staticmethod
    def is_valid_web_bug(bug_data: Dict) -> bool:
        if not bug_data.get('affected_endpoints'):
            raise ValueError(
                "Missing required field for web bug (bug_level 2): affected_endpoints. Web bugs must specify the affected endpoints.")
        return True

    @staticmethod
    def is_valid_network_bug(bug_data: Dict) -> bool:
        if not bug_data.get('port'):
            raise ValueError(
                "Missing required field for network bug (bug_level 4): port. Network bugs must specify the affected port.")
        try:
            port = int(bug_data['port'])
            if port <= 0 or port >= 65535:
                raise ValueError(f"Invalid port number for network bug (bug_level 4): {
                                 port}. Port must be between 1 and 65534.")
        except ValueError:
            raise ValueError(f"Invalid port number for network bug (bug_level 4): {
                             bug_data['port']}. Port must be a valid integer between 1 and 65534.")
        return True

    @staticmethod
    def is_valid_package_bug(bug_data: Dict) -> bool:
        if not bug_data.get('package_name'):
            raise ValueError(
                "Missing required field for package bug (bug_level 6): package_name. Package bugs must specify the name of the affected package.")
        return True

    @classmethod
    def is_valid_cloud_bug(cls, bug_data: Dict) -> bool:
        cloud_type = int(bug_data.get('cloud_type', 0))
        if cloud_type not in [CloudType.OTHERS, CloudType.AWS, CloudType.AZURE, CloudType.GCP]:
            raise ValueError(f"Invalid cloud type for cloud bug (bug_level 5): {
                             cloud_type}. Expected one of {[type.value for type in CloudType]}")

        if not bug_data.get('region'):
            raise ValueError(
                "Missing required field for cloud bug (bug_level 5): region. Cloud bugs must specify the affected region.")

        if cloud_type == CloudType.AWS:
            if bug_data['region'] not in cls.cloud_options['aws_regions']:
                raise ValueError(f"Invalid AWS region for cloud bug (bug_level 5): {
                                 bug_data['region']}. Expected one of {cls.cloud_options['aws_regions']}")
            if not bug_data.get('aws_category'):
                raise ValueError(
                    "Missing required field for AWS cloud bug (bug_level 5): aws_category. AWS cloud bugs must specify the AWS category.")
            if bug_data['aws_category'] not in cls.cloud_options['services']:
                raise ValueError(f"Invalid AWS category for cloud bug (bug_level 5): {
                                 bug_data['aws_category']}. Expected one of {cls.cloud_options['services']}")
            if not bug_data.get('aws_account_id'):
                raise ValueError(
                    "Missing required field for AWS cloud bug (bug_level 5): aws_account_id. AWS cloud bugs must specify the AWS account ID.")

        elif cloud_type == CloudType.AZURE:
            if bug_data['region'] not in cls.cloud_options['azure_regions']:
                raise ValueError(f"Invalid Azure region for cloud bug (bug_level 5): {
                                 bug_data['region']}. Expected one of {cls.cloud_options['azure_regions']}")
            if not bug_data.get('azure_category'):
                raise ValueError(
                    "Missing required field for Azure cloud bug (bug_level 5): azure_category. Azure cloud bugs must specify the Azure category.")
            if not bug_data.get('azure_resource'):
                raise ValueError(
                    "Missing required field for Azure cloud bug (bug_level 5): azure_resource. Azure cloud bugs must specify the Azure resource.")

        elif cloud_type == CloudType.GCP:
            if bug_data['region'] not in cls.cloud_options['gcp_regions']:
                raise ValueError(f"Invalid GCP region for cloud bug (bug_level 5): {
                                 bug_data['region']}. Expected one of {cls.cloud_options['gcp_regions']}")
            if not bug_data.get('gcp_project_id'):
                raise ValueError(
                    "Missing required field for GCP cloud bug (bug_level 5): gcp_project_id. GCP cloud bugs must specify the GCP project ID.")
            if not bug_data.get('gcp_resource_id'):
                raise ValueError(
                    "Missing required field for GCP cloud bug (bug_level 5): gcp_resource_id. GCP cloud bugs must specify the GCP resource ID.")

        return True


def unicode_to_ascii(text):
    ascii_text = unicodedata.normalize('NFKD', text).encode(
        'ASCII', 'ignore').decode('ASCII')
    replacements = {
        '"': '"',
        '"': '"',
        ''': "'",
        ''': "'",
        '–': '-',
        '—': '-',
        '…': '...'
    }
    for unicode_char, ascii_char in replacements.items():
        ascii_text = ascii_text.replace(unicode_char, ascii_char)
    ascii_text = re.sub(r'[^\x00-\x7F]+', '', ascii_text)
    return ascii_text


def detect_encoding(file_path):
    with open(file_path, 'rb') as file:
        raw_data = file.read()
    result = chardet.detect(raw_data)
    return result['encoding']


def convert_and_validate_csv(input_file: str, output_file: str) -> Tuple[List[Dict], List[str]]:
    input_encoding = detect_encoding(input_file)
    print(f"Detected encoding: {input_encoding}")

    valid_data = []
    errors = []

    with open(input_file, 'r', newline='', encoding=input_encoding) as infile, \
            open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames

        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        # Start from 2 to account for header row
        for row_num, row in enumerate(reader, start=2):
            converted_row = {k: unicode_to_ascii(v) for k, v in row.items()}

            try:
                if BugsValidator.is_valid_bug_data(converted_row):
                    valid_data.append(converted_row)
                    writer.writerow(converted_row)
            except ValueError as e:
                errors.append(f"Error in row {row_num}: {str(e)}")

    return valid_data, errors


# Usage
input_file = "csv_bugs.csv"
output_file = "converted_and_validated_bugs.csv"

valid_data, errors = convert_and_validate_csv(input_file, output_file)

print(f"Conversion and validation complete. Output written to {output_file}")
print(f"Number of valid rows: {len(valid_data)}")
print(f"Number of errors: {len(errors)}")

if errors:
    print("\nErrors:")
    for error in errors:
        print(error)
