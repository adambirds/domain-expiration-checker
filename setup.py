from setuptools import setup, find_packages

setup(
    name = "dns-domain-expiration-checker",
    version = "6.0",
    author = "ADB Web Designs",
    author_email = "adam.birds@adbwebdesigns.co.uk",
    url = 'https://github.com/adb-web-designs/dns-domain-expiration-checker.git',
    description = "DNS Domain Expiration Checker",
    keywords = "DNS Domain Expiration Bind",
    packages = find_packages(),
    install_requires = ['python-dateutil'],
)
