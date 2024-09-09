import csv
import unicodedata
import re
import chardet
from typing import Dict, List, Tuple
from enum import IntEnum
import ipaddress

class AssetType(IntEnum):
    UNKNOWN = 0
    WEB = 1
    MOBILE = 2
    NETWORK = 3
    CLOUD = 4
    # ... (add all other asset types here)
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
        if 0 <= int(asset_data.get('asset_type', 0)) <= 222:
            asset_type = int(asset_data['asset_type'])
            if asset_type in [AssetType.WEB, AssetType.MOBILE]:
                if asset_type == AssetType.WEB:
                    web_target = asset_data.get('asset_target') or asset_data.get('target', '')
                    if not cls.is_valid_url(web_target):
                        raise ValueError("Invalid web target")
            if asset_type == AssetType.NETWORK:
                network_target = asset_data.get('asset_target') or asset_data.get('ipaddress') or asset_data.get('target')
                if network_target:
                    target_format = cls.get_network_target_format(network_target)
                    if target_format not in ["ipaddress", "hostname"]:
                        raise ValueError("Invalid network target")
            if asset_type > 4 and not asset_data.get('asset_target') and asset_type != 11:
                raise ValueError("Invalid target")

            # Validate sensitivity
            asset_data['sensitivity'] = cls.validate_optional_field(
                "sensitivity", list(range(5)), asset_data.get('sensitivity', 0)
            )

            # Validate exposed
            asset_data['exposed'] = cls.validate_optional_field(
                "exposed", [1, 2], asset_data.get('exposed', 1)
            )

            # Validate cloud type for cloud assets
            if asset_type == AssetType.CLOUD:
                asset_data['cloud_type'] = cls.validate_optional_field(
                    "cloud_type", [1, 2, 3, 4], asset_data.get('cloud_type', 1)
                )

            return True
        raise ValueError("Invalid asset type")

    @staticmethod
    def is_valid_url(url: str) -> bool:
        regex = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return re.match(regex, url) is not None

    @staticmethod
    def is_valid_ipaddress(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def get_network_target_format(target: str) -> str:
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        hostname_pattern = r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))*$'
        if re.match(ip_pattern, target):
            return "ipaddress"
        elif re.match(hostname_pattern, target):
            return "hostname"
        else:
            return "invalid"

    @staticmethod
    def validate_optional_field(name: str, validator: List[int], value: str) -> int:
        try:
            result = int(float(value))
            if result not in validator:
                raise ValueError
            return result
        except ValueError:
            raise ValueError(f"Invalid {name}")

    @staticmethod
    def validate_exclude_ips(asset_data: Dict) -> List[str]:
        validated_exclude_ips = []
        exclude_ip = asset_data.get('exclude_ip', '')
        if exclude_ip:
            for eip in exclude_ip.split(','):
                eip = eip.strip()
                if not AssetValidator.is_valid_ipaddress(eip):
                    raise ValueError(f"Invalid exclude_ip: {eip}")
                validated_exclude_ips.append(eip)
        return validated_exclude_ips

    @staticmethod
    def is_valid_container_image(url: str) -> bool:
        regex = re.compile(
            r'^(?:(?=[^:\/]{1,253})(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*(?::[0-9]{1,5})?/)?((?![._-])(?:[a-z0-9._-]*)(?<![._-])(?:/(?![._-])[a-z0-9._-]*(?<![._-]))*)(?::(?![.-])[a-zA-Z0-9_.-]{1,128})?$',
            re.IGNORECASE)
        return re.match(regex, url) is not None

def unicode_to_ascii(text):
    ascii_text = unicodedata.normalize('NFKD', text).encode('ASCII', 'ignore').decode('ASCII')
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

        for row_num, row in enumerate(reader, start=2):  # Start from 2 to account for header row
            converted_row = {k: unicode_to_ascii(v) for k, v in row.items()}
            
            try:
                if AssetValidator.is_valid_asset_data(converted_row):
                    valid_data.append(converted_row)
                    writer.writerow(converted_row)
            except ValueError as e:
                errors.append(f"Error in row {row_num}: {str(e)}")

    return valid_data, errors

# Usage
input_file = "csv_assets.csv"
output_file = "converted_and_validated_assets.csv"

valid_data, errors = convert_and_validate_csv(input_file, output_file)

print(f"Conversion and validation complete. Output written to {output_file}")
print(f"Number of valid rows: {len(valid_data)}")
print(f"Number of errors: {len(errors)}")

if errors:
    print("\nErrors:")
    for error in errors:
        print(error)

