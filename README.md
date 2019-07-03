# AWS_rally
rally_AWS
1)After download and install orginal elastic/rally code at https://github.com/elastic/rally 2)Modify code with the client.py and metrics.py under rally/esrally.

sample run command at terminal

#amazon_aws_log_in with client-option (keyID, key and region pass in command) $ esrally --pipeline benchmark-only --track=geonames --target-host=https://search-your-domain.us-west-1.es.amazonaws.com:443 --client-options="use_ssl:true, verify_certs:true,aws_access_key_id:'YOURKEYID',aws_secret_access_key:'YOURACCESSKEY',region:'us-west-1', amazon_aws_log_in:'client_option'" --test-mode

#amazon_aws_log_in with os.environment (environment variables) $ esrally --pipeline benchmark-only --track-path=~/.rally/benchmarks/tracks/tutorial --target-host=https://awsdomaincluster.us-west-1.es.amazonaws.com:443 --client-options="use_ssl:true, verify_certs:true,region:'us-west-1',amazon_aws_log_in:'os_environment'" --test-mode

#default (example: login in opendistro basic auth) $ esrally --pipeline benchmark-only --track-path=~/.rally/benchmarks/tracks/tutorial --target-host=http://localhost:9200 --client-options="use_ssl:true,basic_auth_user:'admin',basic_auth_password:'admin',verify_certs:false" --test-mode
