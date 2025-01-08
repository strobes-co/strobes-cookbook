import csv
import unicodedata
import re
import chardet
from typing import Dict, List, Tuple
from enum import IntEnum
import ipaddress


class AssetType(IntEnum):
    UNKNOWN_ASSET = 0
    WEB = 1
    MOBILE = 2
    NETWORK = 3
    CLOUD = 4
    WEBSITE = 5
    API_SERVICE = 6
    CODE_REPO = 7
    WEB_SERVER = 8
    DB_SERVER = 9
    CONTAINER = 10
    CONTAINER_IMAGE = 11
    FIREWALL = 12
    ROUTER = 13
    SWITCH = 14
    NETWORK_HUB = 15
    PRINTER = 16
    GENERIC_SERVER = 17
    WAP = 18
    MAIL_SERVER = 19
    DNS_SERVER = 20
    DHCP_SERVER = 21
    ENDPOINT = 22
    NETWORK_STORAGE = 23
    VM = 24
    AWS_API_GATEWAY = 25
    AWS_CLOUDFRONT = 26
    AWS_CLOUDWATCH = 27
    AWS_DYNAMODB = 28
    AWS_EBS = 29
    AWS_EC2 = 30
    AWS_ECR = 31
    AWS_ECS = 32
    AWS_EFS = 33
    AWS_EKS = 34
    AWS_OPENSEARCH = 35
    AWS_QLDB = 36
    AWS_ROUTE_53 = 37
    AWS_SAGEMAKER = 38
    AWS_SIMPLE_NOTIFICATION_SERVICE = 39
    AWS_SIMPLE_QUEUE_SERVICE = 40
    AWS_S3 = 41
    AWS_VPC = 42
    AWS_CLOUDFORMATION = 43
    AWS_CLOUDTRAIL = 44
    AWS_CLOUDBUILD = 45
    AWS_CONFIG = 46
    AWS_ELASTIC_BEAN_STALK = 47
    AWS_KEY_MANAGEMENT_SERVICE = 48
    AWS_SECRETS_MANAGER = 49
    AWS_SHIELD = 50
    AWS_AUTO_SCALING = 51
    AWS_WAF = 52
    AWS_DATA_MIGRATION_SERVICE = 53
    AWS_ELB = 54
    AWS_EMR = 55
    AWS_GUARD_DUTY = 56
    AWS_IAM = 57
    AWS_CODEBUILD = 58
    AWS_LAMBDA = 59
    AWS_RDS = 60
    AWS_REDSHIFT_V2 = 61
    AWS_SSM = 62
    GCP_BIG_QUERY = 63
    GCP_COMPUTE_ENGINE = 64
    GCP_DNS = 65
    GCP_IAM = 66
    GCP_CKM = 67
    GCP_CLOUD_LOGGING = 68
    GCP_CLOUD_SQL = 69
    GCP_CLOUD_STORAGE = 70
    AZURE_COMPUTE = 71
    AZURE_CONTAINER_INSTANCES = 72
    AZURE_IAM = 73
    AZURE_KEY_VAULT = 74
    AZURE_FIREWALL = 75
    AZURE_LB = 76
    AZURE_WAF = 77
    AZURE_DNS = 78
    AZURE_ACTIVE_DIRECTORY = 79
    AZURE_SQL_DB = 80
    AZURE_BLOB_STORAGE = 81
    AZURE_COSMOS_DB = 82
    AZURE_KUBERNETES_SERVICE = 83
    AZURE_CONTAINER_REGISTRY = 84
    AZURE_FILES = 85
    AZURE_MANAGED_DISKS = 86
    AZURE_PRIVATE_LINK = 87
    PACKAGE = 88
    AWS_APP_RUNNER = 89
    AWS_BATCH = 90
    AWS_EC2_IMAGE_BUILDER = 91
    AWS_LIGHTSAIL = 92
    AWS_SAR = 93
    AWS_DOCUMENTDB = 94
    AWS_ELASTICACHE = 95
    AWS_KEYSPACES = 96
    AWS_MEMORYDB = 97
    AWS_NEPTUNE = 98
    AWS_SECURITY_GROUPS = 99
    AWS_CERTIFICATE_MANAGER = 100
    AWS_CLOUDHSM = 101
    AWS_COGNITO = 102
    AWS_DETECTIVE = 103
    AWS_DIRECTORY_SERVICE = 104
    AWS_INSPECTOR = 105
    AWS_MACIE = 106
    AWS_RAM = 107
    AWS_SECURITY_HUB = 108
    AWS_BACKUP = 109
    AWS_EDR = 110
    AWS_FSX = 111
    AWS_S3_GLACIER = 112
    AWS_MQ = 113
    AWS_REDSHIFT = 114
    AWS_AUTO_SCALING_GROUP = 115
    AWS_AUTO_SCALING_LAUNCH_CONFIGURATION = 116
    AWS_AUTO_SCALING_SCALING_POLICY = 117
    AWS_BACKUP_VAULT = 118
    AWS_BACKUP_PLAN = 119
    AWS_CLOUDFORMATION_TYPE = 120
    AWS_CLOUDFORMATION_STACK = 121
    AWS_CLOUDFRONT_DISTRIBUTION = 122
    AWS_CLOUDFRONT_STREAMING_DISTRIBUTION = 123
    AWS_CLOUDFRONT_FUNCTIONS = 124
    AWS_CLOUDHSM_HSM = 125
    AWS_CLOUDHSM_HAPG = 126
    AWS_CODEBUILD_BUILD = 127
    AWS_CODEBUILD_PROJECT = 128
    AWS_CODEBUILD_REPORT = 129
    AWS_CONFIG_AGGREGATION_AUTHORIZATION = 130
    AWS_CONFIG_RULE = 131
    AWS_CONFIG_CONFIGURATION_AGGREGATOR = 132
    AWS_CONFIG_CONFORMANCE_PACK = 133
    AWS_CONFIG_ORGANIZATION_CONFIG_RULE = 134
    AWS_CONFIG_ORGANIZATION_CONFORMANCE_PACK = 135
    AWS_DATA_MIGRATION_SERVICE_ENDPOINT = 136
    AWS_DATA_MIGRATION_SERVICE_REPLICATION_INSTANCE = 137
    AWS_DATA_MIGRATION_SERVICE_REPLICATION_TASK = 138
    AWS_DOCUMENTDB_DBCLUSTER = 139
    AWS_DOCUMENTDB_DBINSTANCE = 140
    AWS_DOCUMENTDB_GLOBALCLUSTER = 141
    AWS_ECS_CLUSTER = 142
    AWS_ECS_SERVICE = 143
    AWS_ECS_CONTAINER_INSTANCE = 144
    AWS_ELASTICACHE_CACHE_CLUSTER = 145
    AWS_ELASTICACHE_REPLICATION_GROUP = 146
    AWS_EMR_CLUSTER = 147
    AWS_EMR_NOTEBOOK_EXECUTION = 148
    AWS_EMR_STUDIO = 149
    AWS_EMR_INSTANCE = 150
    AWS_FSX_ASSOCIATION = 151
    AWS_FSX_BACKUP = 152
    AWS_FSX_FILE_SYSTEM = 153
    AWS_FSX_STORAGE_VIRTUAL_MACHINE = 154
    AWS_FSX_VOLUME = 155
    AWS_GUARD_DUTY_FINDING = 156
    AWS_GUARD_DUTY_PUBLISHING_DESTINATION = 157
    AWS_IAM_USER = 158
    AWS_IAM_GROUP = 159
    AWS_IAM_ROLE = 160
    AWS_IAM_POLICY = 161
    AWS_IAM_INSTANCE_PROFILE = 162
    AWS_EC2_IMAGE_BUILDER_COMPONENT_VERSION = 163
    AWS_EC2_IMAGE_BUILDER_CONTAINER_RECIPE = 164
    AWS_EC2_IMAGE_BUILDER_DISTRIBUTION_CONFIGURATION = 165
    AWS_EC2_IMAGE_BUILDER_IMAGE_VERSION = 166
    AWS_EC2_IMAGE_BUILDER_IMAGE_PIPELINE = 167
    AWS_EC2_IMAGE_BUILDER_IMAGE_RECIPE = 168
    AWS_EC2_IMAGE_BUILDER_INFRASTRUCTURE_CONFIGURATION = 169
    AWS_INSPECTOR_ASSESSMENT_RUN = 170
    AWS_INSPECTOR_FINDING = 171
    AWS_LIGHTSAIL_ALARM = 172
    AWS_LIGHTSAIL_BUCKET = 173
    AWS_LIGHTSAIL_CERTIFICATE = 174
    AWS_LIGHTSAIL_CONTAINER_SERVICE = 175
    AWS_LIGHTSAIL_DISK = 176
    AWS_LIGHTSAIL_DISTRIBUTION = 177
    AWS_LIGHTSAIL_DOMAIN = 178
    AWS_LIGHTSAIL_INSTANCE = 179
    AWS_LIGHTSAIL_KEY_PAIR = 180
    AWS_LIGHTSAIL_LOAD_BALANCER = 181
    AWS_LIGHTSAIL_RELATIONAL_DATABASE = 182
    AWS_LIGHTSAIL_STATIC_IP = 183
    AWS_MEMORYDB_ACLS = 184
    AWS_MEMORYDB_CLUSTER = 185
    AWS_NEPTUNE_DB_CLUSTER_ENDPOINT = 186
    AWS_NEPTUNE_DB_CLUSTER = 187
    AWS_NEPTUNE_DB_INSTANCE = 188
    AWS_NEPTUNE_GLOBAL_CLUSTER = 189
    AWS_QLDB_LEDGER = 190
    AWS_QLDB_STREAM = 191
    AWS_RDS_DB_PROXY = 192
    AWS_RDS_DB_CLUSTER = 193
    AWS_RDS_DB_INSTANCE = 194
    AWS_RAM_RESOURCE = 195
    AWS_RAM_RESOURCE_SHARE = 196
    AWS_SAGEMAKER_IMAGE = 197
    AWS_SAGEMAKER_ENDPOINT = 198
    AWS_SAGEMAKER_DOMAIN = 199
    AWS_SAGEMAKER_CODE_REPOSITORY = 200
    AWS_SAGEMAKER_WORK_TEAM = 201
    AWS_SAGEMAKER_WORK_FORCE = 202
    AWS_SAGEMAKER_NOTEBOOK_INSTANCE = 203
    AWS_SAGEMAKER_MODEL = 204
    AWS_SECURITY_HUB_PRODUCT = 205
    AWS_SECURITY_HUB_STANDARD = 206
    AWS_SECURITY_HUB_STANDARD_CONTROL = 207
    AWS_SECURITY_HUB_INSIGHT = 208
    AWS_SIMPLE_NOTIFICATION_SERVICE_TOPIC = 209
    AWS_SIMPLE_NOTIFICATION_SERVICE_PLATFORM_APPLICATION = 210
    AWS_SUBNET = 211
    AWS_ACCOUNT = 212
    GCP_FIREWALL = 213
    GCP_SUBNET = 214
    GCP_VPC = 215
    GCP_KEY_RESOURCE_MANAGEMENT = 216
    GCP_ACCOUNT = 217
    GCP_SECURITY_GROUP = 218
    GCP_IAM_USER = 219
    GCP_IAM_ROLE = 220
    GCP_IAM_POLICY = 221
    USER = 222


class CloudType(IntEnum):
    OTHERS = 1
    AWS = 2
    AZURE = 3
    GCP = 4


class Sensitivity(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Exposed(IntEnum):
    PUBLIC = 1
    PRIVATE = 2


class AssetValidator:
    @classmethod
    def is_valid_asset_data(cls, asset_data: Dict) -> bool:
        """
        Validate the asset data based on its asset type.

        Args:
            asset_data (Dict): The asset data to validate.

        Returns:
            bool: True if the asset data is valid, raises ValueError otherwise.
        """
        asset_type = cls.validate_asset_type(asset_data)

        AssetValidator.validate_exclude_ips(asset_data)
        cls.validate_sensitivity(asset_data)
        cls.validate_exposed(asset_data)

        if asset_type in [AssetType.WEB, AssetType.MOBILE, AssetType.NETWORK]:
            cls.validate_asset_target(asset_data)

        if asset_type in [AssetType.WEB, AssetType.MOBILE]:
            cls.validate_web_mobile_asset(asset_data, asset_type)
        elif asset_type == AssetType.NETWORK:
            cls.validate_network_asset(asset_data)
        elif asset_type == AssetType.CLOUD:
            cls.validate_cloud_asset(asset_data)

        return True

    @staticmethod
    def get_network_ip_target_format(target: str) -> str:
        """
        Get the format of a network IP target.

        Args:
            target (str): The network IP target.

        Returns:
            str: The format of the network IP target.
        """
        if AssetValidator.is_valid_ipaddress(target):
            return "ipaddress"
        else:
            return "invalid"

    @staticmethod
    def get_network_hostname_target_format(target: str) -> str:
        """
        Get the format of a network hostname target.

        Args:
            target (str): The network hostname target.

        Returns:
            str: The format of the network hostname target.
        """
        hostname_pattern = r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*$"
        if re.match(hostname_pattern, target):
            return "hostname"
        else:
            return "invalid"

    @staticmethod
    def get_network_macaddress_target_format(target: str) -> str:
        """
        Get the format of a network MAC address target.

        Args:
            target (str): The network MAC address target.

        Returns:
            str: The format of the network MAC address target.
        """
        macaddress_pattern = (
            r"([0-9A-F]{2}[:]){5}[0-9A-F]{2}|" r"([0-9A-F]{2}[-]){5}[0-9A-F]{2}"
        )
        if re.match(
            macaddress_pattern,
            string=target,
            flags=re.IGNORECASE,
        ):
            return "mac_address"
        else:
            return "invalid"

    @staticmethod
    def validate_mac(mac_address: str) -> bool:
        """
        Validate a MAC address.

        Args:
            mac_address (str): The MAC address to validate.

        Returns:
            bool: True if the MAC address is valid, False otherwise.
        """
        is_valid_mac = re.match(
            r"([0-9A-F]{2}[:]){5}[0-9A-F]{2}|" r"([0-9A-F]{2}[-]){5}[0-9A-F]{2}",
            string=mac_address,
            flags=re.IGNORECASE,
        )
        try:
            return bool(is_valid_mac.group())  # True if match
        except AttributeError:
            return False

    @staticmethod
    def validate_asset_type(asset_data: Dict) -> int:
        """
        Validate the asset type field in the asset data.

        Args:
            asset_data (Dict): The asset data to validate.

        Returns:
            int: The validated asset type.
        """
        try:
            asset_type = int(asset_data.get("asset_type", 0))
            if 0 <= asset_type <= 222:
                return asset_type
            else:
                raise ValueError(
                    f"Invalid asset type: {asset_type}. Expected a value between 0 and 222."
                )
        except ValueError:
            raise ValueError(
                f"Invalid asset type: {asset_data.get('asset_type')}. Expected an integer between 0 and 222."
            )

    @classmethod
    def validate_web_mobile_asset(cls, asset_data: Dict, asset_type: int):
        """
        Validate the fields specific to web and mobile assets.

        Args:
            asset_data (Dict): The asset data to validate.
            asset_type (int): The type of the asset.
        """
        if asset_type == AssetType.WEB:
            web_target = (
                asset_data.get("asset_target")
                or asset_data.get("target", "")
                or asset_data.get("name")
            )
            if not cls.is_valid_url(web_target):
                raise ValueError(
                    f"Invalid web target for Web asset (asset_type 1): {web_target}. Expected a valid URL."
                )

    @classmethod
    def validate_network_asset(cls, asset_data: Dict):
        """
        Validate the fields specific to network assets.

        Args:
            asset_data (Dict): The asset data to validate.
        """
        network_targets = []
        network_ips = []

        if asset_data.get("ipaddress"):
            if "-" in asset_data.get("ipaddress"):
                network_ips.extend(asset_data.get("ipaddress").split("-"))
            else:
                network_ips.append(asset_data.get("ipaddress"))

        if asset_data.get("target"):
            network_targets.append(asset_data.get("target"))

        if asset_data.get("asset_target"):
            network_targets.append(asset_data.get("asset_target"))

        if asset_data.get("hostname"):
            network_targets.append(asset_data.get("hostname"))

        if asset_data.get("mac_address"):
            network_targets.append(asset_data.get("mac_address"))

        if not network_targets and not network_ips:
            raise ValueError(
                "Missing network target for Network asset (asset_type 3). Expected a valid IP address or hostname in 'asset_target', 'ipaddress', or 'target' field."
            )

        for network_ip in network_ips:
            target_format = cls.get_network_ip_target_format(network_ip)
            if target_format == "invalid":
                raise ValueError(
                    f"Invalid network ip for Network asset (asset_type 3): {network_ip}. Expected a valid IP address."
                )

        for network_target in network_targets:
            ip_target_format = cls.get_network_ip_target_format(network_target)
            hostname_target_format = cls.get_network_hostname_target_format(
                network_target
            )
            mac_address_format = cls.get_network_macaddress_target_format(
                network_target
            )
            if (
                ip_target_format == "invalid"
                and hostname_target_format == "invalid"
                and mac_address_format == "invalid"
            ):
                raise ValueError(
                    f"Invalid network target for Network asset (asset_type 3): {network_target}. Expected a valid IP address or hostname."
                )

        if mac_address := asset_data.get("mac_address"):
            if not AssetValidator.validate_mac(mac_address):
                raise ValueError(
                    f"Invalid network mac address for Network asset (asset_type 3): {network_target}. Expected mac address."
                )

    @classmethod
    def validate_cloud_asset(cls, asset_data: Dict):
        """
        Validate the fields specific to cloud assets.

        Args:
            asset_data (Dict): The asset data to validate.
        """
        cloud_type = cls.validate_optional_field(
            "cloud_type", [1, 2, 3, 4], asset_data.get("cloud_type", 1)
        )
        asset_data["cloud_type"] = cloud_type

    @staticmethod
    def validate_other_asset(asset_data: Dict):
        """
        Validate the fields specific to other assets.

        Args:
            asset_data (Dict): The asset data to validate.
        """
        if not asset_data.get("asset_target"):
            raise ValueError(
                f"Missing asset_target for asset type {asset_data.get('asset_type')}. All assets with type > 4 (except 11) must have an asset_target."
            )

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """
        Validate a URL.

        Args:
            url (str): The URL to validate.

        Returns:
            bool: True if the URL is valid, False otherwise.
        """
        regex = re.compile(
            r"^(?:http|ftp)s?://"  # http:// or https://
            # domain...
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"
            r"localhost|"  # localhost...
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
            r"(?::\d+)?"  # optional port
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )
        return re.match(regex, url) is not None

    @staticmethod
    def is_valid_ipaddress(ip: str) -> bool:
        """
        Validate an IP address.

        Args:
            ip (str): The IP address to validate.

        Returns:
            bool: True if the IP address is valid, False otherwise.
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def get_network_target_format(target: str) -> str:
        """
        Get the format of a network target.

        Args:
            target (str): The network target.

        Returns:
            str: The format of the network target.
        """
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        hostname_pattern = r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*$"
        if re.match(ip_pattern, target):
            return "ipaddress"
        elif re.match(hostname_pattern, target):
            return "hostname"
        else:
            return "invalid"

    @staticmethod
    def validate_optional_field(name: str, validator: List[int], value: str) -> int:
        """
        Validate an optional field.

        Args:
            name (str): The name of the field.
            validator (List[int]): The list of valid values.
            value (str): The value to validate.

        Returns:
            int: The validated value.
        """
        try:
            result = int(float(value))
            if result not in validator:
                raise ValueError(
                    f"Invalid {name}: {result}. Expected one of {validator}."
                )
            return result
        except ValueError:
            raise ValueError(
                f"Invalid {name}: {value}. Expected an integer value from {validator}."
            )

    @classmethod
    def validate_sensitivity(cls, asset_data: Dict):
        """
        Validate the sensitivity field in the asset data.

        Args:
            asset_data (Dict): The asset data to validate.
        """
        asset_data["sensitivity"] = cls.validate_optional_field(
            "sensitivity", list(range(5)), asset_data.get("sensitivity", 0)
        )

    @classmethod
    def validate_exposed(cls, asset_data: Dict):
        """
        Validate the exposed field in the asset data.

        Args:
            asset_data (Dict): The asset data to validate.
        """
        asset_data["exposed"] = cls.validate_optional_field(
            "exposed", [1, 2], asset_data.get("exposed", 1)
        )

    @classmethod
    def validate_exclude_ips(cls, asset_data: Dict) -> List[str]:
        """
        Validate the exclude IPs field in the asset data.

        Args:
            asset_data (Dict): The asset data to validate.

        Returns:
            List[str]: The list of validated exclude IPs.
        """
        validated_exclude_ips = []
        exclude_ip = asset_data.get("exclude_ip", "")
        if exclude_ip:
            for eip in exclude_ip.split(","):
                eip = eip.strip()
                if not cls.is_valid_ipaddress(eip):
                    raise ValueError(
                        f"Invalid exclude_ip: {eip}. Expected a valid IP address."
                    )
                validated_exclude_ips.append(eip)
        return validated_exclude_ips

    @staticmethod
    def is_valid_container_image(url: str) -> bool:
        """
        Validate a container image URL.

        Args:
            url (str): The container image URL to validate.

        Returns:
            bool: True if the container image URL is valid, False otherwise.
        """
        regex = re.compile(
            r"^(?:(?=[^:\/]{1,253})(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*(?::[0-9]{1,5})?/)?((?![._-])(?:[a-z0-9._-]*)(?<![._-])(?:/(?![._-])[a-z0-9._-]*(?<![._-]))*)(?::(?![.-])[a-zA-Z0-9_.-]{1,128})?$",
            re.IGNORECASE,
        )
        return re.match(regex, url) is not None

    @staticmethod
    def validate_asset_target(asset_data: Dict):
        """
        Validate the asset target field in the asset data.

        Args:
            asset_data (Dict): The asset data to validate.
        """
        asset_type = asset_data.get("asset_type")

        if asset_type == AssetType.WEB:
            if not (
                asset_data.get("asset_target")
                or asset_data.get("target")
                or asset_data.get("name")
            ):
                raise ValueError(
                    f"Missing asset target or asset name for asset type {asset_data.get('asset_type')} ."
                )

        elif asset_type == AssetType.MOBILE:
            if not (
                asset_data.get("asset_target")
                or asset_data.get("target")
                or asset_data.get("package")
                or asset_data.get("name")
            ):
                raise ValueError(
                    f"Missing asset target or asset name for asset type {asset_data.get('asset_type')} ."
                )

        elif asset_type == AssetType.NETWORK:
            if not (
                asset_data.get("asset_target")
                or asset_data.get("target")
                or asset_data.get("ipaddress")
                or asset_data.get("hostname")
                or asset_data.get("mac_address")
            ):
                raise ValueError(
                    f"Missing asset target or asset name for asset type {asset_data.get('asset_type')} ."
                )

        if not (
            asset_data.get("asset_target")
            or asset_data.get("target")
            or asset_data.get("name")
        ):
            raise ValueError(
                f"Missing asset target or asset name for asset type {asset_data.get('asset_type')} ."
            )


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


def clean_asset_data(asset_data: Dict) -> Dict:
    """
    Clean the asset data by removing extra whitespace and newlines.

    Args:
        asset_data (Dict): The asset data to clean.

    Returns:
        Dict: The cleaned asset data.
    """

    def clean_value(value: str) -> str:
        cleaned = re.sub(r"\s+", " ", value.strip())
        cleaned = cleaned.replace("\n", "").replace("\t", "")
        return cleaned

    important_fields = [
        "asset_target",
        "target",
        "ipaddress",
        "hostname",
        "exclude_ip",
        "container_image",
        "cloud_account_id",
        "cloud_region",
    ]

    cleaned_data = {}
    for key, value in asset_data.items():
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
    Convert and validate the asset data from a CSV file.

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
            cleaned_row = clean_asset_data(converted_row)  # Clean the data

            try:
                if AssetValidator.is_valid_asset_data(cleaned_row):
                    valid_data.append(cleaned_row)
                    writer.writerow(cleaned_row)
            except ValueError as e:
                errors.append(f"Error in row {row_num}: {str(e)}")

    return valid_data, errors


# Usage
input_file = "import_assets_from_csv_template(1).csv"
output_file = "converted_and_validated_assets.csv"

valid_data, errors = convert_and_validate_csv(input_file, output_file)

print(f"Conversion and validation complete. Output written to {output_file}")
print(f"Number of valid rows: {len(valid_data)}")
print(f"Number of errors: {len(errors)}")

if errors:
    print("\nErrors:")
    for error in errors:
        print(error)
