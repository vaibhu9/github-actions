import json
from datetime import datetime

def convert_zap_to_sarif(zap_json):
    """
    Convert ZAP JSON report to SARIF format
    """
    # Initialize SARIF structure
    sarif_output = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OWASP ZAP",
                        "informationUri": "https://www.zaproxy.org/",
                        "version": zap_json.get("@version", ""),
                        "rules": []
                    }
                },
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "timestamp": zap_json.get("@generated", datetime.utcnow().isoformat())
                    }
                ]
            }
        ]
    }

    # Map ZAP risk levels to SARIF level
    risk_level_map = {
        "0": "note",       # Informational
        "1": "note",       # Low
        "2": "warning",    # Medium
        "3": "error"       # High
    }

    # Process each site and its alerts
    for site in zap_json.get("site", []):
        for alert in site.get("alerts", []):
            # Create rule if not exists
            rule_id = f"ZAP-{alert['pluginid']}"
            rule = {
                "id": rule_id,
                "shortDescription": {
                    "text": alert.get("name", "")
                },
                "fullDescription": {
                    "text": alert.get("desc", "").replace("<p>", "").replace("</p>", " ").strip()
                },
                "help": {
                    "text": f"Description: {alert.get('desc', '').replace('<p>', '').replace('</p>', ' ').strip()} Solution: {alert.get('solution', '').replace('<p>', '').replace('</p>', ' ').strip()} Reference: {alert.get('reference', '').replace('<p>', '').replace('</p>', ' ').strip()}"
                },
                "properties": {
                    "security-severity": alert.get("riskcode", "0")
                }
            }

            # Add rule if not already present
            if rule not in sarif_output["runs"][0]["tool"]["driver"]["rules"]:
                sarif_output["runs"][0]["tool"]["driver"]["rules"].append(rule)

            # Process each instance of the alert
            for instance in alert.get("instances", []):
                result = {
                    "ruleId": rule_id,
                    "level": risk_level_map.get(alert.get("riskcode", "0"), "note"),
                    "message": {
                        "text": alert.get("desc", "").replace("<p>", "").replace("</p>", " ").strip()
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": instance.get("uri", "")
                                }
                            }
                        }
                    ],
                    "properties": {
                        "issue_confidence": alert.get("confidence", ""),
                        "instance_method": instance.get("method", ""),
                        "instance_param": instance.get("param", ""),
                        "instance_attack": instance.get("attack", ""),
                        "instance_evidence": instance.get("evidence", ""),
                        "instance_otherinfo": instance.get("otherinfo", ""),
                        "cwe_id": alert.get("cweid", ""),
                        "wasc_id": alert.get("wascid", "")
                    }
                }
                sarif_output["runs"][0]["results"].append(result)

    return sarif_output

def main():
    try:
        # Read input file
        with open('report_json.json', 'r') as f:
            zap_json = json.load(f)
        
        # Convert to SARIF
        sarif_output = convert_zap_to_sarif(zap_json)
        
        # Write output file with compact JSON
        with open('zap_report.sarif', 'w') as f:
            json.dump(sarif_output, f, separators=(',', ':'))
            
        print("Successfully converted ZAP report to SARIF format")
        
    except Exception as e:
        print(f"Error converting report: {e}")
        raise

if __name__ == "__main__":
    main()