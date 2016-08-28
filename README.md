# censys_certif_crawl.py

A script to retrieve the certificate transparancy information from Censys.

This information can be used for OSINT recon.

# Configuration

All the configuration is done in the ini file censys.ini. You need to get an API key from Censys and add the SECRET and UID.

# Usage

Use the script from the command line and give the search query as an argument.

For example to search for certificates related to ".be" (Belgium) you can use

```
censys_certif_crawl.py ".be"
```

# Database

All the data is stored in a sqlite database with three tables
- subject_dn
- dns_names
- issuer_dn

You can use the database to analyze the information that was retrieved from Censys.
