"""
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

"""

import sys
import re
import json
import os
import time
import hashlib
import shutil
import requests
from collections import defaultdict
from urllib.parse import urlparse, unquote
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from PIL import Image
import cv2
from extract_msg import Message
from email import message_from_file, policy
from email.header import decode_header
from email.parser import BytesParser, Parser
import base64
import email
import dkim
import dns.resolver
import pytz
import datetime