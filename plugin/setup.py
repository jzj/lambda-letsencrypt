import setuptools
from setuptools import find_packages

setuptools.setup(
    name='certbot-lambda-s3',
    version='0.1',
    packages=['certbot_lambda_s3'],
    include_package_data=True,
    install_requires=[
        'certbot',
        'zope.interface',
        'boto3',
    ],
    entry_points={
        'certbot.plugins': [
            'lambda-s3 = certbot_lambda_s3.certbot_lambda_s3:Authenticator',
        ],
    },
)
