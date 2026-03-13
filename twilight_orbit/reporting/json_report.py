import json

def export(scan_results: dict, output_path: str | None=None) -> str:
    json_str = json.dumps(scan_results, indent=2, default=str)
    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(json_str)
    return json_str