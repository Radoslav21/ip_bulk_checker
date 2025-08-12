# ip_bulk_checker

Bulk check IP's

'''
    usage: ip_reputation.py [-h] --in INFILE [--out OUTFILE] [--max-parallel MAX_PARALLEL] [--rps RPS] [--max-age MAX_AGE] [--api-key API_KEY]

    AbuseIPDB bulk checker:

    Трябва да имате .env файл, в който се съдържа API ключа на AbuseIPDB, по този начин:
    ABUSEIPDB_KEY=<your_key>

    options:
    -h, --help            show this help message and exit
    --in INFILE           Файл с IP адреси (по 1 на ред).
    --out OUTFILE         CSV изход.
    --max-parallel MAX_PARALLEL
                            Макс. едновременни заявки (default: 10).
    --rps RPS             Макс. заявки/секунда (default: 1.0).
    --max-age MAX_AGE     maxAgeInDays (default: 365).
    --api-key API_KEY     API ключ (ако не ползваш ABUSEIPDB_KEY).

'''
