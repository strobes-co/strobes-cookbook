# Comprehensive Guide to Building Custom Connectors with Strobes Script Executor

## Overview

Strobes Script Executor allows you to create custom integrations by writing Python scripts that fetch vulnerability and asset data from external sources. This guide will walk you through the process of building a custom connector from scratch.

## Script Structure Requirements

Every custom connector must follow these structural requirements:

1. **Start with a `run()` function**: Your entire script logic must be contained within a function named `run()`
2. **End with execution**: The script must end with `raw_output = run()`
3. **Return format**: The `run()` function must return a dictionary with two keys:
   - `bugsList`: List of vulnerability objects
   - `assetsList`: List of asset objects

## Basic Template

```python
def run():
    # Import statements go here
    import requests
    import json
    from enum import Enum
    
    # Your integration logic here
    
    # Must return this structure
    return {"bugsList": bug_list, "assetsList": asset_list}

raw_output = run()
```

## Data Structure Specifications

### Asset Structure

Assets represent the targets being scanned (applications, repositories, hosts, etc.).

```python
raw_asset = {
    "name": "asset_name",        # Required: Unique name of the asset
    "type": 7,                   # Required: Asset type (see Asset Types section)
    "url": "https://example.com" # Optional: URL associated with the asset
}
```

### Bug (Vulnerability) Structure

Bugs represent security vulnerabilities found in your assets.

```python
raw_bug = {
    "title": "SQL Injection in Login",                    # Required: Brief title
    "description": "Detailed description of the issue",   # Required: Full description
    "severity": 4,                                        # Required: 1-5 (Info to Critical)
    "CVSS": 7.5,                                         # Optional: CVSS score
    "CVE": ["CVE-2021-1234"],                           # Optional: List of CVE IDs
    "CWE": ["79", "89"],                                # Optional: List of CWE IDs (numbers only)
    "asset": raw_asset,                                  # Required: Associated asset object
    "duplication_keys": ["issue_id"],                    # Required: Fields for deduplication
    "deduplication_data": {"issue_id": "unique_id"},    # Required: Deduplication values
    "use_default_deduplication": False,                  # Optional: Use Strobes default dedup
    "ticketing_meta": {                                  # Optional: External ticket info
        "issue_key": "JIRA-123",
        "url": "https://jira.example.com/JIRA-123",
        "tracker_slug": "jira"
    }
}
```

## Essential Components

### 1. Severity Mapping

Create an enum to map various severity naming conventions to Strobes' 1-5 scale:

```python
class SeverityType(Enum):
    critical = 5
    blocker = 5
    high = 4
    major = 4
    medium = 3
    moderate = 3
    low = 2
    minor = 2
    info = 1
    informational = 1
    none = 1
```

### 2. CVSS Score Conversion

Convert severity levels to CVSS scores:

```python
def severity_to_cvss(severity: int) -> float:
    """Converts severity in range [1-5] inclusive to normalized CVSS score."""
    return {5: 9.1, 4: 6.9, 3: 4.1, 2: 0.1}.get(severity, 0.0)
```

### 3. API Authentication

Store API keys using environment variables:

```python
keys = []
keys.append(os.getenv("API_KEY_1"))
keys.append(os.getenv("API_KEY_2"))
```

## Complete Example: Building a Custom Connector

Here's a complete example that demonstrates all concepts:

```python
def run():
    import requests
    import json
    import re
    import os
    from enum import Enum
    
    # Configuration
    API_KEY = os.getenv("CUSTOM_API_KEY")
    API_URL = "https://api.security-tool.com/v1"
    
    # Severity mapping
    class SeverityType(Enum):
        critical = 5
        high = 4
        medium = 3
        low = 2
        info = 1
    
    def severity_to_cvss(severity: int) -> float:
        return {5: 9.1, 4: 6.9, 3: 4.1, 2: 0.1}.get(severity, 0.0)
    
    def fetch_vulnerabilities():
        """Fetch vulnerabilities from external API"""
        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.get(f"{API_URL}/vulnerabilities", headers=headers, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error fetching vulnerabilities: {e}")
            return []
    
    def process_vulnerabilities(raw_data):
        """Transform external data to Strobes format"""
        bug_list = []
        asset_list = []
        seen_assets = set()
        
        for vuln in raw_data:
            try:
                # Extract asset information
                asset_name = vuln.get("target", "Unknown")
                asset_url = vuln.get("target_url", "")
                
                # Create asset object
                raw_asset = {
                    "name": asset_name,
                    "type": 7,  # Application type
                    "url": asset_url
                }
                
                # Add to asset list if not already present
                if asset_name not in seen_assets:
                    asset_list.append(raw_asset)
                    seen_assets.add(asset_name)
                
                # Extract vulnerability details
                title = vuln.get("title", "Untitled Vulnerability")
                description = vuln.get("description", "No description provided")
                
                # Map severity
                severity_str = vuln.get("severity", "medium").lower()
                severity_value = getattr(SeverityType, severity_str, SeverityType.medium).value
                cvss_score = severity_to_cvss(severity_value)
                
                # Extract CVE/CWE
                cve_list = re.findall(r"CVE-\d{4}-\d{4,7}", description)
                cwe_list = [cwe.replace("CWE-", "") for cwe in re.findall(r"CWE-\d+", description)]
                
                # Create bug object
                raw_bug = {
                    "title": title,
                    "description": description,
                    "severity": severity_value,
                    "CVSS": cvss_score,
                    "CVE": cve_list,
                    "CWE": cwe_list,
                    "asset": raw_asset,
                    "duplication_keys": ["vulnerability_id"],
                    "deduplication_data": {"vulnerability_id": vuln.get("id", "")},
                    "use_default_deduplication": False
                }
                
                # Add external ticket info if available
                if vuln.get("ticket_id"):
                    raw_bug["ticketing_meta"] = {
                        "issue_key": vuln.get("ticket_id"),
                        "url": vuln.get("ticket_url", ""),
                        "tracker_slug": "jira"
                    }
                
                bug_list.append(raw_bug)
                
            except Exception as e:
                print(f"Error processing vulnerability: {e}")
                continue
        
        return bug_list, asset_list
    
    # Main execution
    raw_vulnerabilities = fetch_vulnerabilities()
    bug_list, asset_list = process_vulnerabilities(raw_vulnerabilities)
    
    # Return required structure
    return {"bugsList": bug_list, "assetsList": asset_list}

raw_output = run()
```

## Best Practices

### 1. Error Handling
Always wrap API calls and data processing in try-except blocks:

```python
try:
    response = requests.get(url, timeout=30)
    response.raise_for_status()
except requests.RequestException as e:
    print(f"API request failed: {e}")
    return []
```

### 2. Pagination
Handle paginated APIs efficiently:

```python
def fetch_all_data(api_url, headers):
    all_data = []
    offset = 0
    limit = 100
    
    while True:
        response = requests.get(
            f"{api_url}?offset={offset}&limit={limit}",
            headers=headers
        )
        data = response.json()
        all_data.extend(data["items"])
        
        if len(data["items"]) < limit:
            break
            
        offset += limit
    
    return all_data
```

### 3. Deduplication
Implement proper deduplication to avoid duplicate vulnerabilities:

```python
"duplication_keys": ["source_id", "asset_name"],
"deduplication_data": {
    "source_id": vuln.get("id"),
    "asset_name": asset.get("name")
}
```

### 4. Data Validation
Validate and sanitize data before creating objects:

```python
# Ensure required fields are present
if not vuln.get("title") or not vuln.get("target"):
    print(f"Skipping invalid vulnerability: {vuln}")
    continue

# Sanitize severity values
severity = vuln.get("severity", "medium").lower()
if severity not in ["critical", "high", "medium", "low", "info"]:
    severity = "medium"
```

## Asset Types Reference

Common asset types in Strobes:

- `1`: IP Address
- `2`: Domain
- `3`: Network Range
- `4`: Mobile Application
- `5`: Source Code Repository
- `6`: Container Image
- `7`: Web Application
- `8`: API Endpoint
- `9`: Cloud Resource

## Advanced Features

### 1. Multiple Data Sources
Combine data from multiple APIs:

```python
def run():
    sources = [
        {"key": os.getenv("SOURCE1_KEY"), "url": "https://api1.com"},
        {"key": os.getenv("SOURCE2_KEY"), "url": "https://api2.com"}
    ]
    
    all_bugs = []
    all_assets = []
    
    for source in sources:
        bugs, assets = fetch_from_source(source)
        all_bugs.extend(bugs)
        all_assets.extend(assets)
    
    return {"bugsList": all_bugs, "assetsList": all_assets}
```

### 2. Data Enrichment
Enhance vulnerability data with additional context:

```python
def enrich_vulnerability(vuln, asset):
    # Add business context
    vuln["description"] += f"\n\nBusiness Impact: {assess_business_impact(asset)}"
    
    # Add remediation guidance
    if vuln.get("CWE"):
        vuln["description"] += f"\n\nRemediation: {get_remediation_for_cwe(vuln['CWE'][0])}"
    
    return vuln
```

### 3. Custom Filtering
Filter vulnerabilities based on custom criteria:

```python
def should_include_vulnerability(vuln):
    # Skip informational findings in production
    if vuln.get("severity") == 1 and "production" in vuln.get("asset", {}).get("name", "").lower():
        return False
    
    # Skip false positives
    if vuln.get("confidence", 100) < 70:
        return False
    
    return True
```

## Testing Your Connector

1. **Test locally first**: Run your script outside Strobes to ensure it returns the correct structure
2. **Validate the output**: Check that all required fields are present
3. **Test with sample data**: Start with a small dataset before processing everything
4. **Monitor execution time**: Ensure your script completes within timeout limits

## Troubleshooting

Common issues and solutions:

1. **Missing imports**: All imports must be inside the `run()` function
2. **Environment variables**: Ensure all required environment variables are set
3. **API timeouts**: Set appropriate timeout values for API calls
4. **Memory issues**: Process data in chunks for large datasets
5. **Invalid data types**: Ensure severity is an integer (1-5) and CVSS is a float

## Conclusion

Building custom connectors with Strobes Script Executor allows you to integrate any security tool or data source into your vulnerability management workflow. By following this guide and the provided patterns, you can create robust connectors that seamlessly import vulnerability and asset data into Strobes.

Remember to always test thoroughly and handle errors gracefully to ensure reliable operation in production environments.
