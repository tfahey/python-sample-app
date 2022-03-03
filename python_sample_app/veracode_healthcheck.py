'''
Check the status of all the APIs supported by the veracode_api_py package.
For each API, print out the name of the API and the status string.
If any APIs had a status other than 'UP' then print a warning message.

'''
from veracode_api_py.healthcheck import Healthcheck

veracode_healthcheck = Healthcheck.status(0)
veracode_healthcheck_dict = dict(veracode_healthcheck)
apiStatus = True
for key in veracode_healthcheck.keys():
    print("Status of", veracode_healthcheck[key]['name'], "is", veracode_healthcheck[key]['status'])
    if 'UP' != veracode_healthcheck[key]['status']:
        apiStatus = False
if not apiStatus:
    errorString = ("*" * 20) + " WARNING! " + ("*" * 20) + "\n"
    errorString += "    One or more APIs have a status issue\n"
    errorString += ("*" * 20) + " WARNING! " + ("*" * 20) + "\n"
    print(errorString)
