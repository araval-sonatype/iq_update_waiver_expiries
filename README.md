# iq_update_waiver_expiries

usage: iq_update_waiver_expiries.py [-h] -s SERVER_URL -u USERNAME -p PASSWORD
                                    [-e [OLD_EXPIRY_DATE]]
                                    [-d [NEW_EXPIRY_DAYS_FROM_NOW]]
                                    [-fa APPLICATION_REGEX]
                                    [-fo ORGANIZATION_REGEX]
                                    [-c CATEGORIES [CATEGORIES ...]]

Connects to IQ and updates waivers that have been set to expire on a given
date, or never, to a new date.

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER_URL         URL of IQ instance.
  -u USERNAME           IQ user's username.
  -p PASSWORD           IQ user's password.
  -e [OLD_EXPIRY_DATE]  The old expiry date to update. If not assigned it will
                        default to "never" expire. Must be in yyyy-MM-dd
                        format if set. Defaults to None or "never" expire.
  -d [NEW_EXPIRY_DAYS_FROM_NOW]
                        The number of days from now to set the new expiry.
                        Defaults to 30 days from today.
  -fa APPLICATION_REGEX
                        A regular expression to be matched against application
                        public ID. Can be used in conjunction with the
                        categoires filter.
  -fo ORGANIZATION_REGEX
                        A regular expression to be matched against
                        organization name.
  -c CATEGORIES [CATEGORIES ...]
                        An optional list of application categories to use as a
                        filter for applications.


Usage example:

python iq_update_waiver_expiries.py -s http://localhost:8070 -u admin -p admin -d 14
Deleting waiver 268bd54c1b624479a11a3d97aac66d2c for policy eab7b4aff90944abaaa657da23c9a04a for component "curl".
Creating waiver for policy eab7b4aff90944abaaa657da23c9a04a for component "curl" with matcher strategy EXACT_COMPONENT and new expiry date 2023-12-20T00:00:00.000+0000.
Deleting waiver bef28fd15343439a9335d912f6046d99 for policy b2bb1a3c18e74234ac4200caf77c5620 for component "cookiecutter".
Creating waiver for policy b2bb1a3c18e74234ac4200caf77c5620 for component "cookiecutter" with matcher strategy ALL_VERSIONS and new expiry date 2023-12-20T00:00:00.000+0000.
Deleting waiver 8680aa9c44f84b678efb6ec557d3e5c7 for policy 4350f0caa188410692cc7c6c632c7b34 for component "".
Creating waiver for policy 4350f0caa188410692cc7c6c632c7b34 for component "" with matcher strategy ALL_COMPONENTS and new expiry date 2023-12-20T00:00:00.000+0000.
