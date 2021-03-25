from configparser import ConfigParser

"""
AUTH

secret is a key used to encrypt and decrypt session tokens, this value must be changed or you will be in danger of an 
account breach.

captcha_fonts is a list of paths to font files. In the example data, raleway.regular.ttf is in the project root.
However if it were in lets say in the resources directory,  the path may look like 
resources/captcha/raleway.regular.ttf. You can seperate the font file paths via a comma.

TORTOISE

This section of configures the tortoise-orm. A majority of these fields should be pretty self explanatory.

models is a list of python files that contain database models. You will need to add your own models to the list. For 
example: asyncauth.core.models, yourpackage.core.models.

generate specifies if tortoise-orm should generate tables in the database.

TWILIO

This section configures TWILIO, the service asyncauth uses to send text messages containing a verification code.

from is a phone number that TWILIO provides you to send text messages from.

token is a secret key that TWILIO provides.

sid is a security identifier that TWILIO provides.

All of this information can be obtained when registering on TWILIO.

SMTP

This section configures SMTP, the protocol asyncauth uses to emails containing a verification code.

host The smtp server host.

port The smtp server port.

from The address an email is being sent from.

username the smtp server access username.

password the smtp server access password.

tls If an SMTP server supports direct connection via TLS/SSL, set this true.

start_tls Many SMTP servers support the STARTTLS extension over port 587. When using STARTTLS, the initial connection is
made over plaintext, and after connecting a STARTTLS command is sent, which initiates the upgrade to a secure 
connection. To connect to a server that uses STARTTLS, set this true.

Both tls and start_tls cannot be true. Either both can be false or one can be true. Ignoring this warning will result in 
errors.
"""
config_path = './auth.ini'
config = ConfigParser()
config.read(config_path)
