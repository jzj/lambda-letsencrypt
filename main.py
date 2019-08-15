import boto3
from botocore.exceptions import ClientError
import certbot.main
import datetime
import os
import subprocess
import shutil
import logging
import tarfile
import sys

import aws

env = {}

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class LoggerWriter:
    def write(self, message):
        return True

    def isatty(self):
        return False


sys.stdout = LoggerWriter()
sys.stderr = LoggerWriter()


def unlock():
    logger.debug('Removing lock file')
    aws.delete_file(env['bucket'], env['bucket_dir'] + '/.lock')


def lock():
    logger.debug('Creating lock file')
    aws.put_object('', env['bucket_dir'] + '/.lock', env['bucket'])


def read_file(path):
    with open(path, 'r') as file:
        contents = file.read()
    return contents


def get_certificate_path(certname):
    path = env['config_dir'] + '/live/' + certname + '/'
    return {
        'certificate': read_file(path + 'cert.pem'),
        'private_key': read_file(path + 'privkey.pem'),
        'certificate_chain': read_file(path + 'chain.pem')
    }


def cleanup():

    # TODO:
    # Check if any certificate has been updated, skip upload to S3 if it doesnt

    logger.info('Compressing certbot config dir')
    with tarfile.open('/tmp/backup.tar.gz', mode='w:gz') as archive:
        archive.add(env['config_dir'], arcname='')

    logger.info('Uploading certbot config dir to S3')
    aws.upload_file('/tmp/backup.tar.gz', env['bucket_dir'] + '/backup.tar.gz',
                    env['bucket'])

    logger.info('Uploading certificates to S3')
    aws.upload_dir(env['config_dir'] + '/live',
                   env['bucket_dir'] + '/' + env['certs'], env['bucket'])

    shutil.rmtree(env['logs_dir'])

    unlock()


def get_env():
    global env

    # Required variables
    env['bucket'] = os.environ['BUCKET']
    env['bucket_dir'] = os.environ['BUCKET_DIR']
    env['email'] = os.environ['EMAIL']

    # Optional variables
    env['s3_role'] = os.getenv('S3_ROLE')
    env['r53_role'] = os.getenv('R53_ROLE')
    env['acm_role'] = os.getenv('ACM_ROLE')

    env['hashs'] = 'Hashs'
    env['certs'] = 'Certs'
    env['config_dir'] = '/tmp/config-dir'
    env['work_dir'] = '/tmp/work-dir'
    env['logs_dir'] = '/tmp/logs-dir'

    if os.environ['LE_ENV'].lower() == 'production':
        env['le_env'] = []
    elif os.environ['LE_ENV'].lower() == 'staging':
        env['le_env'] = ['--staging']
    else:
        raise EnvironmentError

    log_level = os.getenv('LOG_LEVEL', 'default')
    if log_level == 'default':
        logger.info('Log level not defined, using \'info\'')
    env['log_level'] = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL,
        'default': logging.INFO
    }.get(log_level, 'default')


def change_log_level(level):
    global logger
    logger.setLevel(level)
    aws.change_log_level(level)
    for name in logging.Logger.manager.loggerDict.keys():
        if ('boto' in name) or ('urllib3' in name) or (
                's3transfer' in name) or ('boto3' in name) or (
                    'botocore' in name) or ('nose' in name):
            logging.getLogger(name).setLevel(level)


def check_lock():
    logger.debug('Checking if lock exists')
    try:
        aws.download_file(env['bucket_dir'] + '/.lock', '/tmp/.lock',
                          env['bucket'])
        raise FileExistsError
    except FileNotFoundError as e:
        logger.debug('No lock found, continuing')
        lock()


def initialize():
    if env['s3_role'] is not None:
        aws.change_s3_role(env['s3_role'])
    else:
        logger.info('not changing s3 role')
    try:
        check_lock()
    except FileExistsError:
        raise

    logger.info('Changing log level to {}\nnow {}'.format(
        env['log_level'], logger.level))
    change_log_level(env['log_level'])
    aws.change_log_level(env['log_level'])

    # Check if we still have the internal structure cached, if not then download backup from S3
    if not os.path.exists(
            env['config_dir']):  # If destination dir does not exists

        logger.debug('Creating dir {}'.format(env['config_dir']))
        os.makedirs(env['config_dir'])  # Create dir

        logger.info('Attempting to restore internal structure from backup')
        try:
            aws.download_file(env['bucket_dir'] + '/backup.tar.gz',
                              '/tmp/backup.tar.gz', env['bucket'])
            with tarfile.open('/tmp/backup.tar.gz', 'r:gz') as archive:
                archive.extractall(path=env['config_dir'])
        except FileNotFoundError:
            logger.info('No backup found in S3, continuing')
    else:
        logger.info(
            'Internal structure still available, skipping restore from backup')


def abort(msg, remove_lock=True):
    logger.critical(msg)
    if remove_lock:
        unlock()
    return {'statusCode': 400, 'body': msg}


def run_certbot(domains, certname):
    logger.info('Starting certbot')

    assume_role = []
    extra_opts = []
    if env['s3_role'] is not None:
        assume_role = assume_role + [
            '--certbot-lambda-s3:lambda-s3-s3-role', env['s3_role']
        ]
    if env['r53_role'] is not None:
        assume_role = assume_role + [
            '--certbot-lambda-s3:lambda-s3-r53-role', env['r53_role']
        ]
    if env['force']:
        logger.debug('Force value: {}'.format(env['force']))
        extra_opts = extra_opts + ['--force-renewal']
    try:
        certbot.main.main([
            'certonly',  # Obtain a cert but don't install it
            '-n',  # Run in non-interactive mode
            '--agree-tos',  # Agree to the terms of service,
            '--email',
            env['email'],  # Email
            '-d',
            domains,  # Domains to provision certs for
            '--expand',  # Expand certificate with new names
            '--cert-name',
            certname,
            # Override directory paths so script doesn't have to be run as root
            '--config-dir',
            env['config_dir'],
            '--work-dir',
            env['work_dir'],
            '--logs-dir',
            env['logs_dir'],
            '-q',
            '-a',
            'certbot-lambda-s3:lambda-s3',
            '--certbot-lambda-s3:lambda-s3-s3-bucket',
            env['bucket'],
            '--certbot-lambda-s3:lambda-s3-s3-path',
            env['bucket_dir']
        ] + assume_role + env['le_env'] + extra_opts)
    except Exception as e:
        err = 'Certbot failed with the following error:\n{}'.format(e)
        return abort(err)

    logger.info('Cleaning up')
    cleanup()  # Upload internal configuration dir to S3

    return {'statusCode': 200}


def validate_hash(validation):

    try:
        logger.debug('Trying to get file {}:{}'.format(
            env['bucket'],
            env['bucket_dir'] + '/' + env['hashs'] + '/' + validation))
        response = aws.get_file_contents(
            env['bucket'],
            env['bucket_dir'] + '/' + env['hashs'] + '/' + validation)
        status = 200
        logger.debug('Challenge {} answered with {}'.format(
            validation, response))
    except ClientError as e:
        logger.error('Unexpected error when trying to get Hash {}: {}'.format(
            validation, e))
        response = str(e)
        status = 400

    return {'statusCode': status, 'body': response}


def handler(event, context):
    path = event.get('path')
    domains = None

    # Get environment variables
    try:
        get_env()
    except Exception:
        raise

    if path == '/.well-known/provision':  # Requested to provision
        logger.info('Initializing environment')
        try:
            initialize()  # Grab account and certificates from S3
        except FileExistsError:
            err = 'Lock file already exists, aborting'
            return abort(err, False)
        except KeyError as e:
            err = 'Missing environment variable ' + str(e)
            return abort(err)
        except EnvironmentError as e:
            err = 'Invalid environment supplied, choose \'production\' or \'staging\'\n> {}'.format(
                e)
            return abort(err)

        parameters = event.get('queryStringParameters')  # Get parameters

        if 'domains' in parameters:
            domains = parameters['domains']  # Get domains to validate
        else:
            return abort('invalid request, must supply the domains parameter')

        if 'certname' in parameters:
            certname = parameters['certname']
        else:
            domains.split(',')[0]

        if 'force' in parameters:
            if parameters['force'] in [
                    'true', 'True', 'yes', 'Yes', 'enabled', 'Enabled'
            ]:
                env['force'] = True
            else:
                env['force'] = False
        else:
            env['force'] = False

        logger.info(
            'Running certbot for the following domains: {}'.format(domains))

        result = run_certbot(domains, certname)  # Provision certificates

        if result['statusCode'] == 200:
            certificate = get_certificate_path(certname)
            logger.info('Uploading provisioned certs to ACM')
            if env['acm_role'] is not None:
                aws.change_acm_role(env['acm_role'])
            aws.upload_cert_to_acm(certificate, certname)

        return result

    else:  # Replying challenge
        try:
            validation = path.split('/')[-1]  # Get hash
        except Exception:
            logger.error('Invalid URL')
            return {'statusCode': 400}
        logger.warning(event)
        return validate_hash(validation)  # Solve hash challenge
