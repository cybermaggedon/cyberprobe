
from oauth2client.service_account import ServiceAccountCredentials

scopes = ['https://www.googleapis.com/auth/bigquery']

credentials = ServiceAccountCredentials.from_json_keyfile_name(
    'private.json',
    scopes=scopes
    )



from httplib2 import Http
http = Http()
http_auth = credentials.authorize(http)

from apiclient.discovery import build
service = build('bigquery', 'v2', http=http_auth)

#print bq.projects
#print bq.projects().list()

#dsets = bq.datasets.list()

#request = service.projects()
#data = {
#    #...
#    }

#response = request.projects().execute()

datasets = service.datasets()

response = datasets.list(projectId=MY_PROJECT).execute(http)

print 'Datasets:'
for v in response['datasets']:
    print v['datasetReference']['datasetId']


