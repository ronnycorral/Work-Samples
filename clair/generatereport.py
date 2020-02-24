#!/usr/bin/env python

import urllib2
import psycopg2
import datetime
import time
import json
import os
import io
import subprocess
import glob
from os.path import expanduser
from ConfigParser import SafeConfigParser
from shutil import copyfile
import boto3
from botocore.exceptions import ClientError
import requests

# set to length of image list you want to test. 0 for entire list
debug=0

repo_corral = 'docker.aws.corral.com'
json_report_path='/data/web/html/index.html'
clair_bucket='corral-clair-reports'

# images where we want to scan all the tags, not just 'latest' or 'latest' doesn't exist
get_tags_list = ['corral/ubuntu', 'corral/ubuntu-rsync', 'corral/postgres', 'devpi', 'library/cookiedestroy', 'library/ubuntu', 'ubuntu', 'selenium/hub', 'selenium/node-chrome', 'selenium/node-firefox', 'selenium/standalone-chrome', 'selenium/standalone-firefox']

# get docker cred so we can log into docker API for image and tag lists
def get_docker_creds():
   authentication_file_path = expanduser('~') + '/.docker/config.json'

   try:
      with open(authentication_file_path, 'r') as read_file:
         filedata = json.load(read_file)
   except:
         print ('ERROR: %s does not exist' % authentication_file_path )
         exit (1)

   base_64_string = filedata['auths']['docker.aws.corral.com']['auth']

   return base_64_string


def get_image_list(get_tags_list):
   url = 'https://docker.aws.corral.com/v2/_catalog?n=1000'

   docker_cred = get_docker_creds()

   request = urllib2.Request(url)
   request.add_header("Authorization", "Basic %s" % docker_cred)
   try:
       response = urllib2.urlopen(request)
   except urllib2.HTTPError as e:
       print(e)
       print(e.headers)
       exit(1)

   repository = json.loads(response.read().decode('utf-8'))

   image_list = []
   for image in repository['repositories']:
      if image in get_tags_list:
         tags_list = get_tags_for_image(image)
         for tag in tags_list:
            image_list.append(image + ':' + tag)
      else:
         image_list.append(image)

   return image_list

def get_tags_for_image(image):
   url = 'https://docker.aws.corral.com/v2/%s/tags/list' % image

   docker_cred = get_docker_creds()

   request = urllib2.Request(url)
   request.add_header("Authorization", "Basic %s" % docker_cred)
   try:
       response = urllib2.urlopen(request)
       tag_list = json.loads(response.read().decode('utf-8'))
       tags = tag_list['tags']
   except urllib2.HTTPError:
       tags = []

   return tags

# clair puts a row in the 'lock' table when it is updating it's database.
# making sure it's clear before proceeding
def wait_for_clair_db():
   max_minutes=120
   wait_time=5 * 60

   config = SafeConfigParser()
   config.read('/opt/config/clair/clairdb.ini');

   conn_string = 'host=%s port=5432 dbname=%s user=%s password=%s' % (config.get('clairDB','host'), config.get('clairDB','db_name'), config.get('clairDB','user'), config.get('clairDB','pass'))
   conn=psycopg2.connect(conn_string)
   cur = conn.cursor()

   clair_locked = 1
   time_start = datetime.datetime.now()
   while clair_locked:
      time_now = datetime.datetime.now()
      duration = time_now - time_start
      duration_in_s = duration.total_seconds()
      duration_in_minutes = divmod(duration_in_s, 60)[0]

      if duration_in_minutes >= max_minutes:
         print ('ERROR: It has taken over %s minutes for Clair to load the DB' % max_minutes)
         exit(1)

      cur.execute('SELECT count(*) AS exact_count FROM public.lock')
      lock_count = cur.fetchone()
      clair_locked = lock_count[0]
      if clair_locked:
         print ('%s - waiting for Clair DB - %d' % (time_now.strftime("%d-%B-%Y %H:%M:%S"), clair_locked))
         time.sleep(wait_time)
      else:
         print ('%s - Clair DB available - %d' % (time_now.strftime("%d-%B-%Y %H:%M:%S"), clair_locked))

def docker_pull(image):

    process = subprocess.Popen(['docker', 'pull' , image], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output, err) = process.communicate()
    exit_code = process.wait()

    return output, err, exit_code

def clairctl_analyze(image):

    process = subprocess.Popen(['docker', 'exec', 'clairctl', 'clairctl', 'analyze', '-l', image], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output, err) = process.communicate()
    exit_code = process.wait()
    output = "".join(i for i in output if ord(i) < 127)

    return output, err, exit_code

def clairctl_report(image,report_format):

    if report_format == 'json':
       format_option = 'json'
    else:
       format_option = 'html'

    process = subprocess.Popen(['docker', 'exec', 'clairctl', 'clairctl', 'report', '--format', format_option, '-l', image], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output, err) = process.communicate()
    exit_code = process.wait()

    return output, err, exit_code

# returns a vulnerability list sorted by host and vuln level
def parse_jason_report(report_filename):
    vuln_list = []

    try:
        with open(report_filename) as report_json:
            report = json.loads(report_json.read())
    except IOError:
        raise Exception("Error accessing %s", report_filename)

    image_name = report['ImageName'].replace('docker.aws.corral.com/','') + ":" + report['Tag']

    for layer in report['Layers']:
        features = layer['Layer']

        if 'Features' not in features:
           continue

        for feature in features['Features']:
            if 'Vulnerabilities' not in feature:
                continue

            for vulnerability in feature['Vulnerabilities']:
                if vulnerability['Severity'] in ['High', 'Critical', 'Defcon1']:
                    filename = os.path.basename(report_filename)
                    try:
                       description  = vulnerability['Description']
                    except:
                       description = 'No description listed'
                    try:
                       fixed_by  = vulnerability['FixedBy']
                    except:
                       fixed_by = 'No fixed version listed'

                    vuln_info = { 'ImageName':image_name, 'Severity':vulnerability['Severity'], 'PackageName':feature['Name'], 'PackageVersion':feature['Version'], 'Link':vulnerability['Link'], 'ReportPathName':filename, 'Description':description, 'FixedBy':fixed_by, 'CVEName':vulnerability['Name'] }
                    if vuln_info not in vuln_list:
                        vuln_list.append( vuln_info )

    vuln_list.sort(key=lambda elem: elem['Severity'])

    return vuln_list

# Making sure we get the highest severity level
def set_image_severity(vuln_severity, image_severity):

    if vuln_severity == 'Defcon1':
        image_severity = 'Defcon1'
    elif vuln_severity == 'Critical' and image_severity != 'Defcon1' :
        image_severity = 'Critical'
    elif vuln_severity == 'High' and image_severity != 'Defcon1' and image_severity != 'Critical' :
        image_severity = 'High'

    return image_severity

def make_single_vuln_line(vuln_data, temp_report_area):

      cve_link = '<a href="%s">%s</a>' % (vuln_data['Link'], vuln_data['Link'])
      temp_report_area = temp_report_area + ('<tr><td> %s </td><td><b>Current&nbsp;Version:</b><br>%s<br><b>Fixed&nbsp;By:</b><br>%s</td><td> %s </td><td><b>Name: </b>%s<br><b>Link:</b> %s<br><b>Description:</b><br>%s</td></tr>\n' %  (vuln_data['PackageName'], vuln_data['PackageVersion'], vuln_data['FixedBy'],vuln_data['Severity'], vuln_data['CVEName'], cve_link, vuln_data['Description']))

      return temp_report_area

def sort_vuln_list(complete_vuln_list):
   current_image = ''
   image_severity = ''
   temp_report_area = ''
   vuln_report_areas = {'Defcon1':'','Critical':'', 'High':''}
   for vulnerability in complete_vuln_list:
      if vulnerability['ImageName'] == current_image:

         temp_report_area = make_single_vuln_line(vulnerability, temp_report_area)

         image_severity = set_image_severity(vulnerability['Severity'], image_severity)
      else:
         if not image_severity:
            image_severity = vulnerability['Severity']
         vuln_report_areas[image_severity] = vuln_report_areas[image_severity] + temp_report_area

         image_severity = ''
         current_image = vulnerability['ImageName']
         #html_report_path = vulnerability['ReportPathName'].replace('.json','.html')

         #temp_report_area = ('<tr><th colspan=4 bgcolor=lightgrey> <h3>%s</h3>(<a href=/json/%s>json</a>, <a href=/%s>html</a>) </th></tr>\n' %  (vulnerability['ImageName'], vulnerability['ReportPathName'],html_report_path) )
         temp_report_area = ('<tr><th colspan=4 bgcolor=lightgrey> <h3>%s</h3></th></tr>\n' %  (vulnerability['ImageName']) )
         temp_report_area = make_single_vuln_line(vulnerability, temp_report_area)

         image_severity = set_image_severity(vulnerability['Severity'], image_severity)

   vuln_report_areas[image_severity] = vuln_report_areas[image_severity] + temp_report_area

   return vuln_report_areas

def print_json_report(vulns_sorted_by_severity, json_report_path):
   if not os.path.exists(os.path.dirname(json_report_path)):
       os.makedirs(os.path.dirname(json_report_path))
   json_report_file = open(json_report_path,'w')

   d = datetime.datetime.today()
   json_report_file.write("<html><head><title>Docker Imgage Vulnerability Report</title></head><body>")
   json_report_file.write("<h1>Docker Imgage Vulnerability Report</h1>\n")
   json_report_file.write("<p>Created at: %s</p>\n" % d.strftime("%d-%B-%Y %H:%M:%S"))
   json_report_file.write("<table border=1>\n")

   for vuln_level in ['Defcon1', 'Critical', 'High'] :
       if vulns_sorted_by_severity[vuln_level]:
           json_report_file.write('<h2>%s Level Images' % vuln_level)
           json_report_file.write("<table border=1>\n")
           json_report_file.write(vulns_sorted_by_severity[vuln_level])
           json_report_file.write("</table>\n")

   json_report_file.write("</body></html>\n")
   json_report_file.close()

# making sure reports exist for already pulled images
# and touching them so i can find old ones easier
def verify_reports_exist(image_name):
   doc_root = '/data/web/'

   if ':' in image_name:
      image_name = image_name.replace(':','-')
   else:
      image_name = image_name + '-latest'

   image_name = 'analysis-' + image_name.replace('/','-')

   json_report = doc_root + 'json/' + image_name + '.json'

   if os.path.isfile(json_report):
      touch(json_report)
      report_exists = 1
   else:
      print ('REGEN MISSING REPORTS: %s' % image_name)
      report_exists = 0

   return report_exists

def touch(path):
    with io.open(path, 'ab'):
        os.utime(path, None)

def upload_file(file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # Upload the file
    s3_client = boto3.client('s3')
    try:
        s3_client.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        print ('ERROR: %s' % e )
        return False
    return True

def clear_aws_env():
   aws_env_vars = ['AWS_SECRET_KEY', 'AWS_ACCESS_KEY', 'AWS_ACCESS_KEY_ID', 'AWS_SECURITY_TOKEN', 'AWS_SECRET_ACCESS_KEY', 'AWS_DELEGATION_TOKEN']
   for i in aws_env_vars:
      if i in os.environ:
         del os.environ[i]


time_now = datetime.datetime.now()
print ('Secuirty Report Generation Start - %s' % time_now.strftime("%d-%B-%Y %H:%M:%S"))

clear_aws_env()
wait_for_clair_db()

image_list = get_image_list(get_tags_list)

if debug:
   del image_list[debug:]

# this is the getting the images and reports area
for image in image_list:
   image_url = repo_corral + '/' + image
   message, err_message, exit_code =  docker_pull(image_url)

   if exit_code:
      print ('ERROR: non-zero exit code(%d) while pulling IMAGE: %s\nMESSAGE: %s\nERROR: %s' % (exit_code, image_url, message, err_message))
      continue
   elif 'Status: Image is up to date for' in message:
      print ('NO UPDATE FOR: %s' % image_url)
      report_exists = verify_reports_exist(image_url)
      if report_exists:
         continue

   print ('ANALYZING: %s'% image_url)
   message, err_message, exit_code = clairctl_analyze(image_url)
   if err_message:
      print ('ERROR analyzing IMAGE: %s EXIT CODE: (%d)\nMESSAGE: %s\nERROR: %s' % (image_url, exit_code, message, err_message))
   else:
      '''
      message, err_message, exit_code = clairctl_report(image_url,'html')
      if err_message:
         print ('ERROR reporting html IMAGE: %s EXIT CODE: (%d)\nMESSAGE: %s\nERROR: %s' % (image_url, exit_code, message, err_message))
      '''
      message, err_message, exit_code = clairctl_report(image_url,'json')
      if err_message:
         print ('ERROR reporting json IMAGE: %s EXIT CODE: (%d)\nMESSAGE: %s\nERROR: %s' % (image_url, exit_code, message, err_message))

# this is the doing something with the data.
#turn off the temp index updates
subprocess.call(["sed", "-i.bak", 's/^\(\* \* \* \* \* root \/data\/clair\/maketempindex.sh\)/#\\1/', "/etc/cron.d/clair"])

report_list = sorted(glob.glob("/data/web/json/*.json"))

# get a list of all vulnerabilities
complete_vuln_list = []
for single_json_report in report_list:
   complete_vuln_list = complete_vuln_list + parse_jason_report(single_json_report)
   # copy files to doc root
   report_in_doc_root = single_json_report.replace('/json','/html/json')
   copyfile(single_json_report, report_in_doc_root)

vulns_sorted_by_severity = sort_vuln_list(complete_vuln_list)
print_json_report(vulns_sorted_by_severity, json_report_path)
upload_file(json_report_path,clair_bucket,'clairreport.html')

time_now = datetime.datetime.now()
print ('Secuirty Report Generation Finish - %s' % time_now.strftime("%d-%B-%Y %H:%M:%S"))

if debug == 0:
   instance_id = []
   response = requests.get('http://169.254.169.254/latest/meta-data/instance-id')
   instance_id.append(response.text)
   ec2 = boto3.resource('ec2', region_name='us-east-1')
   ec2.instances.filter(InstanceIds = instance_id).terminate()
