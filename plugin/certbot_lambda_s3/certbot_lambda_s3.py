import zope.interface
from acme import challenges

from certbot import interfaces
from certbot.plugins import common

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

from certbot_dns_route53 import dns_route53

import boto3

from certbot_lambda_s3 import custom_r53


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):

    description = "Obtain certificates using HTTP-01 or DNS challenge modes and using AWS S3 as storage backend"

    MORE_INFO = """\
            Authenticator plugin to run o AWS Lambda using AWS S3 as storage
            backend. This plugin performs HTTP-01 challenge for normal
            certificates and DNS for wildcard certificates. It expects
            that there is Application Loadbalancer configured to serve the
            /.well-known path to this Lambda Function."""

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return self.MORE_INFO

    def __init__(self, *args, **kwargs):
        # Increase boto3 log level to INFO
        logger.info('Changing log level')
        for name in logging.Logger.manager.loggerDict.keys():
            if ('boto' in name) or ('urllib3' in name) or (
                    's3transfer' in name) or ('boto3' in name) or (
                        'botocore' in name) or ('nose' in name):
                logging.getLogger(name).setLevel(logging.INFO)

        self.args = args
        self.kwargs = kwargs
        super(Authenticator, self).__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add):
        add('s3-role', help='S3 role to be assumed before commands')
        add('s3-bucket', help='S3 bucket')
        add('s3-path', help='S3 path inside the bucket')
        add('r53-role', help='Route53 role to be assumed before commands')

    def prepare(self):
        if self.conf('s3-role'):
            logger.info('The following role will be used for S3 access: ' +
                        self.conf('s3-role'))
            sts_client = boto3.client('sts')
            assumed_role_object = sts_client.assume_role(
                RoleArn=self.conf('s3-role'), RoleSessionName="AssumeRoleS3")
            s3_credentials = assumed_role_object['Credentials']
            self.s3_session = boto3.session.Session(
                aws_access_key_id=s3_credentials['AccessKeyId'],
                aws_secret_access_key=s3_credentials['SecretAccessKey'],
                aws_session_token=s3_credentials['SessionToken'], )
            self.s3 = self.s3_session.client('s3')
        else:
            logger.info('Using the current role to access S3')
            self.s3 = boto3.client('s3')

        if self.conf('r53-role'):
            logger.info('The following role will be used for Route53 access: '
                        + self.conf('r53-role'))
            self.r53 = custom_r53.Authenticator(
                self.conf('r53-role'), self.args, self.kwargs)
        else:
            # implement locally due to assume role
            self.r53 = dns_route53.Authenticator(self.args, self.kwargs)

        self.s3_bucket = self.conf('s3-bucket')
        self.s3_path = self.conf('s3-path')

    def get_chall_pref(self, domain):  # pragma: no cover
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        # Return the preferred challenge type by order
        return [challenges.HTTP01, challenges.DNS01]

    def perform_dns(self, achalls):  # Perform the challenge via DNS
        return self.r53.perform(achalls)

    def perform_http(self, achalls,
                     bucket, s3_path):  # Perform the challenge via HTTP-01
        result = []
        for achall in achalls:
            validation = achall.validation(achall.account_key)

            self.s3.put_object(
                Body=validation,
                Bucket=bucket,
                Key=s3_path + '/Hashs/' + validation.split('.')[0])

            result.append(achall.response(achall.account_key))

        return result

    # Implement all methods from IAuthenticator, remembering to add
    # "self" as first argument, e.g. def prepare(self)...

    def perform(self, achalls):
        achalls_http = []
        achalls_dns = []
        responses = []


        for i, achall in enumerate(achalls):

            if isinstance(achall.chall, challenges.DNS01):
                achalls_dns.append(achall)
            else:
                achalls_http.append(achall)

        if achalls_dns:
            responses.extend(self.perform_dns(achalls_dns))
        if achalls_http:
            responses.extend(self.perform_http(achalls_http, self.s3_bucket, self.s3_path))

        return responses

    def cleanup(self, achalls):
        for achall in achalls:
            if isinstance(achall.chall, challenges.DNS01):
                continue
            else:

                for i, achall in enumerate(achalls):
                    validation = achall.validation(achall.account_key)
                    self.s3.delete_object(
                        Bucket=self.s3_bucket,
                        Key=self.s3_path + '/Hashs/' + validation.split('.')[0])
