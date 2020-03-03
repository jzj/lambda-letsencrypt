import collections
import boto3
from certbot_dns_route53._internal import dns_route53
import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class Authenticator(dns_route53.Authenticator):
    def __init__(self, role, *args, **kwargs):
        # Get parent of dns_route53.Authenticator and initialize
        super(dns_route53.Authenticator, self).__init__(*args, **kwargs)

        if role:
            logger.info('Assuming role: ' + role)
            sts_client = boto3.client('sts')
            assumed_role_object = sts_client.assume_role(
                RoleArn=role, RoleSessionName="AssumeRoleR53")
            r53_credentials = assumed_role_object['Credentials']
            self.r53_session = boto3.session.Session(
                aws_access_key_id=r53_credentials['AccessKeyId'],
                aws_secret_access_key=r53_credentials['SecretAccessKey'],
                aws_session_token=r53_credentials['SessionToken'], )
            self.r53 = self.r53_session.client('route53')
        else:
            logger.info('Using current role')
            self.r53 = boto3.client("route53")

        self._resource_records = collections.defaultdict(
            list)  # type: DefaultDict[str, List[Dict[str, str]]]
