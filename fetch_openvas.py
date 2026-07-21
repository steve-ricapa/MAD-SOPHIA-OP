import json
import sys

import requests


sys.stdout.reconfigure(encoding='utf-8')

BASE_URL = 'https://txdxai-flask.replit.app/api'
DEFAULT_EMAIL = 'mifibranoc@mifibra.com'
DEFAULT_PASSWORD = 'pepe123'


def login(email, password):
    response = requests.post(
        f'{BASE_URL}/auth/login',
        json={'email': email, 'password': password},
        timeout=30,
    )
    response.raise_for_status()
    token = response.json().get('access_token')
    if not token:
        raise RuntimeError('Login sin access_token')
    return token


def download_scans(token, scanner_type):
    response = requests.get(
        f'{BASE_URL}/scans',
        headers={'Authorization': f'Bearer {token}'},
        params={'scanner_type': scanner_type, 'limit': 100},
        timeout=60,
    )
    response.raise_for_status()
    data = response.json()

    output_file = f'todos_los_{scanner_type}.json'
    with open(output_file, 'w', encoding='utf-8') as file_obj:
        json.dump(data, file_obj, indent=2, ensure_ascii=False)

    print(f'Se guardo la respuesta completa en {output_file}')
    print(f"Scans encontrados: {data.get('count', 0)}")

    return data


def download_findings(token, scan_summary_id, domain='soc'):
    response = requests.get(
        f'{BASE_URL}/scans/{scan_summary_id}/findings',
        headers={'Authorization': f'Bearer {token}'},
        params={'domain': domain},
        timeout=60,
    )
    response.raise_for_status()
    return response.json()


def download_scans_with_findings(token, scanner_type):
    scans_payload = download_scans(token, scanner_type)
    scans = scans_payload.get('scans', [])

    detailed_scans = []
    scans_without_findings = []

    for scan in scans:
        scan_summary_id = scan.get('id')
        if scan_summary_id is None:
            continue

        findings_payload = download_findings(token, scan_summary_id)
        findings_count = findings_payload.get('count', 0)

        if findings_count == 0:
            scans_without_findings.append({
                'id': scan_summary_id,
                'scan_id': scan.get('scan_id'),
                'scan_name': scan.get('scan_name'),
                'status': scan.get('status'),
            })

        detailed_scans.append({
            'summary': scan,
            'findings_count': findings_count,
            'findings': findings_payload.get('findings', []),
        })

    output_file = f'todos_los_{scanner_type}_con_findings.json'
    with open(output_file, 'w', encoding='utf-8') as file_obj:
        json.dump(
            {
                'scanner_type': scanner_type,
                'count': len(detailed_scans),
                'scans_without_findings_count': len(scans_without_findings),
                'scans_without_findings': scans_without_findings,
                'scans': detailed_scans,
            },
            file_obj,
            indent=2,
            ensure_ascii=False,
        )

    print(f'Se guardo el consolidado con findings en {output_file}')
    print(f'Scans con findings vacios: {len(scans_without_findings)}')


def main():
    scanner_type = sys.argv[1] if len(sys.argv) > 1 else 'wazuh'
    token = login(DEFAULT_EMAIL, DEFAULT_PASSWORD)
    download_scans_with_findings(token, scanner_type)


if __name__ == '__main__':
    main()
