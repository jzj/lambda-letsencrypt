import boto3
from botocore.exceptions import ClientError
import os
import subprocess

import logging

logger = logging.getLogger(__name__)

client_s3 = boto3.client('s3')
resource_s3 = boto3.resource('s3')
client_acm = boto3.client('acm')


def change_acm_role(role):
    global client_acm
    logger.info('The following role will be used for ACM access: ' + role)
    sts_client = boto3.client('sts')
    assumed_role_object = sts_client.assume_role(
        RoleArn=role, RoleSessionName="AssumeRoleACM")
    acm_credentials = assumed_role_object['Credentials']
    acm_session = boto3.session.Session(
        aws_access_key_id=acm_credentials['AccessKeyId'],
        aws_secret_access_key=acm_credentials['SecretAccessKey'],
        aws_session_token=acm_credentials['SessionToken'], )
    client_acm = acm_session.client('acm')


def change_s3_role(role):
    global client_s3
    global resource_s3
    logger.info('The following role will be used for S3 access: ' + role)
    sts_client = boto3.client('sts')
    assumed_role_object = sts_client.assume_role(
        RoleArn=role, RoleSessionName="AssumeRoleS3")
    s3_credentials = assumed_role_object['Credentials']
    s3_session = boto3.session.Session(
        aws_access_key_id=s3_credentials['AccessKeyId'],
        aws_secret_access_key=s3_credentials['SecretAccessKey'],
        aws_session_token=s3_credentials['SessionToken'], )
    client_s3 = s3_session.client('s3')
    resource_s3 = s3_session.resource('s3')


def delete_file(bucket, key):
    client_s3.delete_object(Bucket=bucket, Key=key)


def put_object(body, key, bucket):
    client_s3.put_object(Body=body, Key=key, Bucket=bucket)


def upload_file(source_file, destination_file, bucket):

    try:
        logger.info('Uploading file {} to {} on bucket {}'.format(
            source_file, destination_file, bucket))
        client_s3.upload_file(source_file, bucket, destination_file)
    except ClientError as e:
        logger.error('Unexpected error when uploading file {}: {}'.format(
            source_file, e))


def upload_dir(source_dir, destination_dir, bucket):

    for root, dirs, files in os.walk(
            source_dir):  # Enumerate local files recursively

        for filename in files:  # For each file

            local_path = os.path.join(root,
                                      filename)  # Build the full local path

            relative_path = os.path.relpath(local_path, source_dir)
            s3_path = os.path.join(destination_dir,
                                   relative_path)  # Build the full remote path

            upload_file(local_path, s3_path, bucket)


def download_file(source_file, destination_file, bucket):
    try:

        if not os.path.exists(os.path.dirname(
                destination_file)):  # If destination dir does not exists
            logger.info('Creating dir {}'.format(destination_file))
            os.makedirs(os.path.dirname(destination_file))  # Create dir

        logger.info('Downloading file {} to {} of bucket {}'.format(
            source_file, destination_file, bucket))
        client_s3.download_file(bucket, source_file, destination_file)
        return
    except ClientError as e:
        logger.error('Unexpected error when downloading file {}:\n {}'.format(
            source_file, e))
        raise FileNotFoundError


def get_file_contents(bucket, key):
    try:
        obj = client_s3.get_object(Bucket=bucket, Key=key)  # Get s3 file
        return obj['Body'].read().decode('utf-8')
    except:
        raise


def download_dir(client, resource, dist, local, bucket):

    paginator = client.get_paginator('list_objects')

    for result in paginator.paginate(
            Bucket=bucket, Delimiter='/', Prefix=dist):  # Paginate results

        if result.get('CommonPrefixes') is not None:  # Get all dirs in S3
            for subdir in result.get('CommonPrefixes'):  # For each dir
                download_dir(
                    client, resource, subdir.get('Prefix'), local, bucket
                )  # Recursively get all files and subdirs inside this dir

        for file in result.get('Contents', []):  # For each file
            dest_pathname = os.path.join(local, file.get('Key')).replace(
                env['bucket_dir'], '')  # Build destination path

            if not os.path.exists(os.path.dirname(
                    dest_pathname)):  # If destination dir does not exists
                logger.info('Creating dir {}'.format(dest_pathname))
                os.makedirs(os.path.dirname(dest_pathname))  # Create dir

            if not file.get('Key').endswith('/'):  # If it is not a dir
                logger.info('Downloading file {} to {} from S3'.format(
                    file.get('Key'), dest_pathname))
                resource.meta.client.download_file(
                    bucket, file.get('Key'), dest_pathname)  # Download file


def change_log_level(level):
    global logger
    logger.setLevel(level)
    for name in logging.Logger.manager.loggerDict.keys():
        if ('boto' in name) or ('urllib3' in name) or (
                's3transfer' in name) or ('boto3' in name) or (
                    'botocore' in name) or ('nose' in name):
            logging.getLogger(name).setLevel(level)


def notify_via_sns(topic_arn, domains, certificate):
    process = subprocess.Popen(
        ['openssl', 'x509', '-noout', '-text'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        encoding='utf8')
    stdout, stderr = process.communicate(certificate)

    client = boto3.client('sns')
    client.publish(
        TopicArn=topic_arn,
        Subject='Issued new LetsEncrypt certificate',
        Message='Issued new certificates for domains: ' + domains + '\n\n' +
        stdout, )


def find_existing_cert(certname):
    paginator = client_acm.get_paginator('list_certificates')
    iterator = paginator.paginate(PaginationConfig={'MaxItems': 1000})

    for page in iterator:
        for cert in page['CertificateSummaryList']:
            certificate = client_acm.describe_certificate(
                CertificateArn=cert['CertificateArn'])
            tags = client_acm.list_tags_for_certificate(
                CertificateArn=cert['CertificateArn'])['Tags']
            for tag in tags:
                try:
                    if tag['Key'] == 'Name' and tag['Value'] == certname:
                        logger.debug('Found previous certificate, replacing')
                        return cert
                except KeyError:
                    pass

    logger.debug('Could not find a previous certificate, creating a new one')
    return None


def upload_cert_to_acm(cert, certname):
    existing_cert = find_existing_cert(certname)

    if existing_cert is not None:
        # Update existing certificate
        certificate_arn = existing_cert['CertificateArn']
        acm_response = client_acm.import_certificate(
            CertificateArn=certificate_arn,
            Certificate=cert['certificate'],
            PrivateKey=cert['private_key'],
            CertificateChain=cert['certificate_chain'])
    else:
        # Create a new certificate
        acm_response = client_acm.import_certificate(
            Certificate=cert['certificate'],
            PrivateKey=cert['private_key'],
            CertificateChain=cert['certificate_chain'])
        client_acm.add_tags_to_certificate(
            CertificateArn=acm_response['CertificateArn'],
            Tags=[{
                'Key': 'Name',
                'Value': certname
            }])

    return acm_response['CertificateArn']
