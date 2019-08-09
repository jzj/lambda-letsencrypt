# lambda-letsencrypt

Lambda function used to generate certificates from Let's Encrypt

This lambda function makes a request to Let's Encrypt to generate a certificate
with the supplied names and is able to solve the HTTP-01 and DNS challenges.

It supports requesting normal FQDN and wildcard certificates and renew them if
necessary.

For example, `domains=example.org,*.example.org&certname=example` the certificate
file will have the name `example.pem` and will be imported to ACM with the
name `example`.

After the certificate is generated the script upload it to S3 together with it's
internal state compressed in a tar.gz file and import it to ACM, overwriting an
existing certificate if they have the same name.

This lambda function supports assuming other roles per service, for example the
lambda function uses `role1`, the S3 module uses `role2`, the Route53 module
uses `role3` and the ACM module uses `role4`.

This function should be run only once at a time.

#### Dependencies

* Python 3.6

```
curl -o python3.6.tar.gz https://www.python.org/ftp/python/3.6.8/Python-3.6.8.tgz
tar xvf python3.6.tar.gz
cd Python-3.6.8/
./configure --enable-optimizations --with-ensurepip=install
sudo make altinstall -j $(nproc)
```

* AWS Role

Create a role, import the [policy](https://github.com/chaordic/operations-infra/raw/master/scripts/lambda-letsencrypt/policy.json) and then edit the ROLE variable inside the Makefile with the ARN

#### Configuration

Configuration is done through environment variables defined inside the Makefile

| Variable   	    | Description                                                                       	| Requirement 	| Default Value           	                                    |
|---------------	|-----------------------------------------------------------------------------------	|-------------	|-------------------------------------------------------------	|
| LAMBDA\_ROLE 	    | Name of the role to be used by the lambda function                                	| YES         	|                                                               |
| BUCKET     	    | Name of the S3 bucket to store the certificates and challenges                    	| YES         	| letsencrypt             	                                    |
| BUCKET\_DIR 	    | Directory inside the S3 bucket                                                    	| YES         	| letsencrypt\_internal    	                                    |
| EMAIL      	    | Email for the Let's Encrypt account (used for certificate renewal and revocation) 	| YES         	|                        	                                    |
| LE\_ENV     	    | Let's Encrypt environment (staging/production)                                    	| YES         	| staging                 	                                    |
| S3\_ROLE  	    | Name of the role to be used by the S3 module                                      	| Optional    	|                                                               |
| R53\_ROLE  	    | Name of the role to be used by the Route53 module                                    	| Optional    	|                                                               |
| ACM\_ROLE  	    | Name of the role to be used by the ACM module                                      	| Optional    	|                                                               |
| LOG\_LEVEL  	    | Log level                                                                         	| Optional    	| info                    	                                    |
| TAGS        	    | Lambda function tags                                                              	| Optional    	|                         	                                    |
| FUNCTION\_NAME    | Lambda function name                                                              	| Optional    	| letsencrypt\_internal   	                                    |
| DESCRIPTION 	    | Lambda function description                                                       	| Optional    	| Lambda function used to provision letsencrypt certificates    |
| REGION      	    | Region to deploy the lambda function                                              	| Optional    	| us-east-1               	                                    |
| ZIP\_FILE    	    | Name of the compressed environment file                                           	| Optional    	| lambda-letsencrypt.zip  	                                    |
| MEMORY\_SIZE	    | Maximum memory available to the lambda function                                   	| Optional    	| 192                     	                                    |

#### Create an isolated environment

`make dependencies`

#### Compress the environment

`make pack`

#### Create lambda function

`make create-function EMAIL='admin@example.org' LAMBDA_ROLE='arn:aws:iam::_ACCOUNT_ID1:role/letsencrypt' BUCKET='my-bucket' BUCKET_DIR='letsencrypt' LE_ENV='staging' S3_ROLE='arn:aws:iam::_ACCOUNT_ID2:role/letsencrypt-s3' R53_ROLE='arn:aws:iam::_ACCOUNT_ID3:role/letsencrypt-r53' ACM_ROLE='arn:aws:iam::_ACCOUNT_ID4:role/letsencrypt-acm' TAGS='name1=value1,name2=value2' LOG_LEVEL='warning'`

#### Just upload the compressed environment

`make update-function`

#### Recreate the isolated environment, compress and upload

`make deploy`

#### Request or renew certificate

`curl -L http://<loadbalancer hostname>/.well-known/provision?domains=example.org,*.example.org&certname=example`
