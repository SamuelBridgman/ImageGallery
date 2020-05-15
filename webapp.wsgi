#!/usr/bin/python
import sys
import logging
# logging.basicConfig(stream=sys.stderr)
logging.basicConfig(filename='/var/log/apache2/app.log', level=logging.INFO)

sys.path.insert(0,"/var/www/webApp/")

from webApp import app as application
application.secret_key = 'ThroughTheLookingGlass'
