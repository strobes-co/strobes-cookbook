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
        "aws_regions": [
            "us-east-2",
            "us-east-1",
            "us-west-1",
            "us-west-2",
            "ap-east-1",
            "ap-south-1",
            "ap-northeast-2",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-northeast-1",
            "ca-central-1",
            "cn-north-1",
            "cn-northwest-1",
            "eu-central-1",
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "eu-north-1",
            "sa-east-1",
            "us-gov-east-1",
            "us-gov-west-1",
        ],
        "azure_regions": [
            "eastus",
            "eastus2",
            "southcentralus",
            "westus2",
            "westus3",
            "australiaeast",
            "southeastasia",
            "northeurope",
            "swedencentral",
            "uksouth",
            "westeurope",
            "centralus",
            "northcentralus",
            "westus",
            "southafricanorth",
            "centralindia",
            "eastasia",
            "japaneast",
            "jioindiawest",
            "koreacentral",
            "canadacentral",
            "francecentral",
            "germanywestcentral",
            "norwayeast",
            "switzerlandnorth",
            "uaenorth",
            "brazilsouth",
            "centralusstage",
            "eastusstage",
            "eastus2stage",
            "northcentralusstage",
            "southcentralusstage",
            "westusstage",
            "westus2stage",
            "asia",
            "asiapacific",
            "australia",
            "brazil",
            "canada",
            "europe",
            "global",
            "india",
            "japan",
            "uk",
            "unitedstates",
            "eastasiastage",
            "southeastasiastage",
            "centraluseuap",
            "eastus2euap",
            "westcentralus",
            "southafricawest",
            "australiacentral",
            "australiacentral2",
            "australiasoutheast",
            "japanwest",
            "jioindiacentral",
            "koreasouth",
            "southindia",
            "westindia",
            "canadaeast",
            "francesouth",
            "germanynorth",
            "norwaywest",
            "swedensouth",
            "switzerlandwest",
            "ukwest",
            "uaecentral",
            "brazilsoutheast",
        ],
        "services": ["ec2", "s3", "rds", "elb"],
        "gcp_regions": [
            "asia-east1-a",
            "asia-east1-b",
            "asia-east1-c",
            "asia-east2-a",
            "asia-east2-b",
            "asia-east2-c",
            "asia-northeast1-a",
            "asia-northeast1-b",
            "asia-northeast1-c",
            "asia-northeast2-a",
            "asia-northeast2-b",
            "asia-northeast2-c",
            "asia-northeast3-a",
            "asia-northeast3-b",
            "asia-northeast3-c",
            "asia-south1-a",
            "asia-south1-b",
            "asia-south1-c",
            "asia-south2-a",
            "asia-south2-b",
            "asia-south2-c",
            "asia-southeast1-a",
            "asia-southeast1-b",
            "asia-southeast1-c",
            "asia-southeast2-a",
            "asia-southeast2-b",
            "asia-southeast2-c",
            "australia-southeast1-a",
            "australia-southeast1-b",
            "australia-southeast1-c",
            "australia-southeast2-a",
            "australia-southeast2-b",
            "australia-southeast2-c",
            "europe-central2-a",
            "europe-central2-b",
            "europe-central2-c",
            "europe-north1-a",
            "europe-north1-b",
            "europe-north1-c",
            "europe-southwest1-a",
            "europe-southwest1-b",
            "europe-southwest1-c",
            "europe-west1-b",
            "europe-west1-c",
            "europe-west1-d",
            "europe-west2-a",
            "europe-west2-b",
            "europe-west2-c",
            "europe-west3-a",
            "europe-west3-b",
            "europe-west3-c",
            "europe-west4-a",
            "europe-west4-b",
            "europe-west4-c",
            "europe-west6-a",
            "europe-west6-b",
            "europe-west6-c",
            "europe-west8-a",
            "europe-west8-b",
            "europe-west8-c",
            "europe-west9-a",
            "europe-west9-b",
            "europe-west9-c",
            "me-west1-a",
            "me-west1-b",
            "me-west1-c",
            "northamerica-northeast1-a",
            "northamerica-northeast1-b",
            "northamerica-northeast1-c",
            "northamerica-northeast2-a",
            "northamerica-northeast2-b",
            "northamerica-northeast2-c",
            "southamerica-east1-a",
            "southamerica-east1-b",
            "southamerica-east1-c",
            "southamerica-west1-a",
            "southamerica-west1-b",
            "southamerica-west1-c",
            "us-central1-a",
            "us-central1-b",
            "us-central1-c",
            "us-central1-f",
            "us-east1-b",
            "us-east1-c",
            "us-east1-d",
            "us-east4-a",
            "us-east4-b",
            "us-east4-c",
            "us-east5-a",
            "us-east5-b",
            "us-east5-c",
            "us-south1-a",
            "us-south1-b",
            "us-south1-c",
            "us-west1-a",
            "us-west1-b",
            "us-west1-c",
            "us-west2-a",
            "us-west2-b",
            "us-west2-c",
            "us-west3-a",
            "us-west3-b",
            "us-west3-c",
            "us-west4-a",
            "us-west4-b",
            "us-west4-c",
        ],
    }

    @classmethod
    def is_valid_bug_data(cls, bug_data: Dict) -> bool:
        """
        Validate the bug data based on its bug level.
        
        Args:
            bug_data (Dict): The bug data to validate.
        
        Returns:
            bool: True if the bug data is valid, raises ValueError otherwise.
        """
        cls.has_valid_common_fields(bug_data)
        cls.has_valid_severity(bug_data)

        bug_level = int(bug_data.get("bug_level", 0))
        if bug_level not in [level.value for level in BugLevel]:
            raise ValueError(
                f"Invalid bug level: {bug_level}. Expected one of {[level.value for level in BugLevel]}"
            )

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
    def has_valid_severity(bug_data: Dict) -> bool:
        """
        Validate the severity field in the bug data.
        
        Args:
            bug_data (Dict): The bug data to validate.
        
        Returns:
            bool: True if the severity is valid, raises ValueError otherwise.
        """
        if (not bug_data.get("severity")) or int(bug_data.get("severity")) not in [
            1,
            2,
            3,
            4,
            5,
        ]:
            raise ValueError(
                f"Invalid severity: {bug_data.get('severity')}. Expected one of [1,2,3,4,5]."
            )
        return True

    @staticmethod
    def has_valid_common_fields(bug_data: Dict) -> bool:
        """
        Validate the common fields in the bug data.
        
        Args:
            bug_data (Dict): The bug data to validate.
        
        Returns:
            bool: True if the common fields are valid, raises ValueError otherwise.
        """
        required_fields = ["title", "description", "mitigation"]
        missing_fields = [field for field in required_fields if not bug_data.get(field)]
        if missing_fields:
            raise ValueError(
                f"Missing required common field(s): {', '.join(
                missing_fields)}. All bugs must have a title, description, and mitigation."
            )
        return True

    @staticmethod
    def is_valid_code_bug(bug_data: Dict) -> bool:
        """
        Validate the fields specific to code bugs.
        
        Args:
            bug_data (Dict): The bug data to validate.
        
        Returns:
            bool: True if the code bug fields are valid, raises ValueError otherwise.
        """
        required_fields = [
            "vulnerable_code",
            "file_name",
            "start_line_number",
            "end_line_number",
        ]
        missing_fields = [field for field in required_fields if not bug_data.get(field)]
        if missing_fields:
            raise ValueError(
                f"Missing required field(s) for code bug (bug_level 1): {', '.join(
                missing_fields)}. Code bugs must specify the vulnerable code, file name, and line numbers."
            )
        return True

    @staticmethod
    def is_valid_web_bug(bug_data: Dict) -> bool:
        """
        Validate the fields specific to web bugs.
        
        Args:
            bug_data (Dict): The bug data to validate.
        
        Returns:
            bool: True if the web bug fields are valid, raises ValueError otherwise.
        """
        if not bug_data.get("affected_endpoints"):
            raise ValueError(
                "Missing required field for web bug (bug_level 2): affected_endpoints. Web bugs must specify the affected endpoints."
            )
        return True

    @staticmethod
    def is_valid_network_bug(bug_data: Dict) -> bool:
        """
        Validate the fields specific to network bugs.
        
        Args:
            bug_data (Dict): The bug data to validate.
        
        Returns:
            bool: True if the network bug fields are valid, raises ValueError otherwise.
        """
        if not bug_data.get("port"):
            raise ValueError(
                "Missing required field for network bug (bug_level 4): port. Network bugs must specify the affected port."
            )
        try:
            port = int(bug_data["port"])
            if port <= 0 or port >= 65535:
                raise ValueError(
                    f"Invalid port number for network bug (bug_level 4): {port}. Port must be between 1 and 65534."
                )
        except ValueError:
            raise ValueError(
                f"Invalid port number for network bug (bug_level 4): {bug_data['port']}. Port must be a valid integer between 1 and 65534."
            )
        return True

    @staticmethod
    def is_valid_package_bug(bug_data: Dict) -> bool:
        """
        Validate the fields specific to package bugs.
        
        Args:
            bug_data (Dict): The bug data to validate.
        
        Returns:
            bool: True if the package bug fields are valid, raises ValueError otherwise.
        """
        if not bug_data.get("package_name") or not bug_data.get("affected_versions"):
            raise ValueError(
                "Missing required field for package bug (bug_level 6): package_name. Package bugs must specify the name of the affected package."
            )
        return True

    @classmethod
    def is_valid_cloud_bug(cls, bug_data: Dict) -> bool:
        """
        Validate the fields specific to cloud bugs.
        
        Args:
            bug_data (Dict): The bug data to validate.
        
        Returns:
            bool: True if the cloud bug fields are valid, raises ValueError otherwise.
        """
        cloud_type = int(bug_data.get("cloud_type", 0))
        if cloud_type not in [
            CloudType.OTHERS,
            CloudType.AWS,
            CloudType.AZURE,
            CloudType.GCP,
        ]:
            raise ValueError(
                f"Invalid cloud type for cloud bug (bug_level 5): {cloud_type}. Expected one of {[type.value for type in CloudType]}"
            )

        if not bug_data.get("region"):
            raise ValueError(
                "Missing required field for cloud bug (bug_level 5): region. Cloud bugs must specify the affected region."
            )

        if cloud_type == CloudType.AWS:
            if bug_data["region"] not in cls.cloud_options["aws_regions"]:
                raise ValueError(
                    f"Invalid AWS region for cloud bug (bug_level 5): {bug_data['region']}. Expected one of {cls.cloud_options['aws_regions']}"
                )
            if not bug_data.get("aws_category"):
                raise ValueError(
                    "Missing required field for AWS cloud bug (bug_level 5): aws_category. AWS cloud bugs must specify the AWS category."
                )
            if bug_data["aws_category"] not in cls.cloud_options["services"]:
                raise ValueError(
                    f"Invalid AWS category for cloud bug (bug_level 5): {bug_data['aws_category']}. Expected one of {cls.cloud_options['services']}"
                )
            if not bug_data.get("aws_account_id"):
                raise ValueError(
                    "Missing required field for AWS cloud bug (bug_level 5): aws_account_id. AWS cloud bugs must specify the AWS account ID."
                )

        elif cloud_type == CloudType.AZURE:
            if bug_data["region"] not in cls.cloud_options["azure_regions"]:
                raise ValueError(
                    f"Invalid Azure region for cloud bug (bug_level 5): {bug_data['region']}. Expected one of {cls.cloud_options['azure_regions']}"
                )
            if not bug_data.get("azure_category"):
                raise ValueError(
                    "Missing required field for Azure cloud bug (bug_level 5): azure_category. Azure cloud bugs must specify the Azure category."
                )
            if not bug_data.get("azure_resource"):
                raise ValueError(
                    "Missing required field for Azure cloud bug (bug_level 5): azure_resource. Azure cloud bugs must specify the Azure resource."
                )

        elif cloud_type == CloudType.GCP:
            if bug_data["region"] not in cls.cloud_options["gcp_regions"]:
                raise ValueError(
                    f"Invalid GCP region for cloud bug (bug_level 5): {bug_data['region']}. Expected one of {cls.cloud_options['gcp_regions']}"
                )
            if not bug_data.get("gcp_project_id"):
                raise ValueError(
                    "Missing required field for GCP cloud bug (bug_level 5): gcp_project_id. GCP cloud bugs must specify the GCP project ID."
                )
            if not bug_data.get("gcp_resource_id"):
                raise ValueError(
                    "Missing required field for GCP cloud bug (bug_level 5): gcp_resource_id. GCP cloud bugs must specify the GCP resource ID."
                )

        return True


def unicode_to_ascii(text: str) -> str:
    """
    Convert Unicode text to ASCII.
    
    Args:
        text (str): The text to convert.
    
    Returns:
        str: The converted ASCII text.
    """
    ascii_text = (
        unicodedata.normalize("NFKD", text).encode("ASCII", "ignore").decode("ASCII")
    )
    replacements = {
        '"': '"',
        '"': '"',
        """: "'",
        """: "'",
        "–": "-",
        "—": "-",
        "…": "...",
    }
    for unicode_char, ascii_char in replacements.items():
        ascii_text = ascii_text.replace(unicode_char, ascii_char)
    ascii_text = re.sub(r"[^\x00-\x7F]+", "", ascii_text)
    return ascii_text


def detect_encoding(file_path: str) -> str:
    """
    Detect the encoding of a file.
    
    Args:
        file_path (str): The path to the file.
    
    Returns:
        str: The detected encoding.
    """
    with open(file_path, "rb") as file:
        raw_data = file.read()
    result = chardet.detect(raw_data)
    return result["encoding"]


def clean_bug_data(bug_data: Dict) -> Dict:
    """
    Clean the bug data by removing extra whitespace and newlines.
    
    Args:
        bug_data (Dict): The bug data to clean.
    
    Returns:
        Dict: The cleaned bug data.
    """
    def clean_value(value: str) -> str:
        cleaned = re.sub(r"\s+", " ", value.strip())
        cleaned = cleaned.replace("\n", "").replace("\t", "")
        return cleaned

    important_fields = [
        "title",
        "description",
        "mitigation",
        "vulnerable_code",
        "file_name",
        "affected_endpoints",
        "port",
        "package_name",
        "region",
        "aws_category",
        "aws_account_id",
        "azure_category",
        "azure_resource",
        "gcp_project_id",
        "gcp_resource_id",
    ]

    cleaned_data = {}
    for key, value in bug_data.items():
        if isinstance(value, str):
            if key in important_fields:
                cleaned_data[key] = clean_value(value)
            else:
                cleaned_data[key] = value.strip()
        else:
            cleaned_data[key] = value

    return cleaned_data


def convert_and_validate_csv(
    input_file: str, output_file: str
) -> Tuple[List[Dict], List[str]]:
    """
    Convert and validate the bug data from a CSV file.
    
    Args:
        input_file (str): The path to the input CSV file.
        output_file (str): The path to the output CSV file.
    
    Returns:
        Tuple[List[Dict], List[str]]: A tuple containing the list of valid data and the list of errors.
    """
    input_encoding = detect_encoding(input_file)
    print(f"Detected encoding: {input_encoding}")

    valid_data = []
    errors = []

    with open(input_file, "r", newline="", encoding=input_encoding) as infile, open(
        output_file, "w", newline="", encoding="utf-8"
    ) as outfile:
        reader = csv.DictReader(infile)
        fieldnames = reader.fieldnames

        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row_num, row in enumerate(reader, start=2):
            converted_row = {k: unicode_to_ascii(v) for k, v in row.items()}
            cleaned_row = clean_bug_data(converted_row)  # Clean the data

            try:
                if BugsValidator.is_valid_bug_data(cleaned_row):
                    valid_data.append(cleaned_row)
                    writer.writerow(cleaned_row)
            except ValueError as e:
                errors.append(f"Error in row {row_num}: {str(e)}")

    return valid_data, errors


# Usage
input_file = "import_bugs_from_csv_template(1).csv"
output_file = "converted_and_validated_bugs_final.csv"

valid_data, errors = convert_and_validate_csv(input_file, output_file)

print(f"Conversion and validation complete. Output written to {output_file}")
print(f"Number of valid rows: {len(valid_data)}")
print(f"Number of errors: {len(errors)}")

if errors:
    print("\nErrors:")
    for error in errors:
        print(error)
