import singer
from singer import utils
from target_postgres import target_tools
from target_redshift.s3 import S3

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from target_snowflake.connection import connect
from target_snowflake.snowflake import SnowflakeTarget

LOGGER = singer.get_logger()

REQUIRED_CONFIG_KEYS = [
    'snowflake_account',
    'snowflake_warehouse',
    'snowflake_database',
    'snowflake_username',
    'snowflake_pkb'
]


def main(config, input_stream=None):
    pkb = config.get('snowflake_pkb').encode('utf-8')
    snowflake_private_key = serialization.load_pem_private_key(pkb, None, default_backend()).private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with connect(
            user=config.get('snowflake_username'),
            private_key=snowflake_private_key,
            role=config.get('snowflake_role'),
            authenticator=config.get('snowflake_authenticator', 'snowflake'),
            account=config.get('snowflake_account'),
            warehouse=config.get('snowflake_warehouse'),
            database=config.get('snowflake_database'),
            schema=config.get('snowflake_schema', 'PUBLIC'),
            autocommit=False
    ) as connection:
        s3_config = config.get('target_s3')

        s3 = None
        if s3_config:
            s3 = S3(s3_config.get('aws_access_key_id'),
                    s3_config.get('aws_secret_access_key'),
                    s3_config.get('bucket'),
                    s3_config.get('key_prefix'))

        target = SnowflakeTarget(
            connection,
            s3=s3,
            logging_level=config.get('logging_level'),
            persist_empty_tables=config.get('persist_empty_tables')
        )

        if input_stream:
            target_tools.stream_to_target(input_stream, target, config=config)
        else:
            target_tools.main(target)


def cli():
    args = utils.parse_args(REQUIRED_CONFIG_KEYS)

    main(args.config)
