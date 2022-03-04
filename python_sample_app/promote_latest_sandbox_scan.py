'''
For a specific application, list the sandboxes for the application.
For each of the sandboxes, list the static scans.
Allow the user to select a static scan, and promote the scan to policy.

'''

import sys
import json
import http
import subprocess
import xml.etree.ElementTree as ET


def checkList(ele, prefix):
    for i in range(len(ele)):
        if (isinstance(ele[i], list)):
            checkList(ele[i], prefix+"["+str(i)+"]")
        elif (isinstance(ele[i], str)):
            printField(ele[i], prefix+"["+str(i)+"]")
        else:
            checkDict(ele[i], prefix+"["+str(i)+"]")


def checkDict(jsonObject, prefix):
    for ele in jsonObject:
        if (isinstance(jsonObject[ele], dict)):
            checkDict(jsonObject[ele], prefix+"."+ele)

        elif (isinstance(jsonObject[ele], list)):
            checkList(jsonObject[ele], prefix+"."+ele)

        elif (isinstance(jsonObject[ele], str)):
            printField(jsonObject[ele],  prefix+"."+ele)

def printField(ele, prefix):
    print (prefix, ":" , ele)


def iterate(aDict):
    # Iterating all the fields of the JSON
    for element in aDict:
        # If Json Field value is a Nested Json
        if (isinstance(aDict[element], dict)):
            checkDict(aDict[element], element)
        # If Json Field value is a list
        elif (isinstance(aDict[element], list)):
            checkList(aDict[element], element)
        # If Json Field value is a string
        elif (isinstance(aDict[element], str)):
            printField(aDict[element], element)


def getApplicationGUID():
    getApplicationJSON = subprocess.run(
        ['http', '--ignore-stdin', '--auth-type=veracode_hmac', 'https://api.veracode.com/appsec/v1/applications/'],
        capture_output=True)
    print("The list of applications has been retrieved")
    applicationsJSON = json.loads(getApplicationJSON.stdout)
    embeddedApplicationsDict = applicationsJSON['_embedded']
    # iterate(embeddedApplicationsDict)
    anApplicationList = embeddedApplicationsDict['applications']
    print("The application list has ", len(anApplicationList), "elements")
    # [iterate(app) for app in anApplicationList]
    # [print(app['guid']) for app in anApplicationList]
    myAppName = 'VerademoTF'
    for app in anApplicationList:
        # print(app['profile']['name'], app['guid'])
        # print("The app profile name is type: ", type(app['profile']['name']))
        appProfileName = app['profile']['name']
        # if appProfileName == myAppName :
        #    print("The GUID is ", app['guid'])
        if app['profile']['name'] == myAppName:
            print("For application name", app['profile']['name'], "The GUID is", app['guid'])
            myAppGUID = app['guid']
    return myAppGUID


def getSandboxes(appGUID):
    # For the given GUID, get a list of sandboxes
    apiUrl = "https://api.veracode.com/appsec/v1/applications/" + appGUID + "/sandboxes"
    getSandboxesJSON = subprocess.run(['http', '--ignore-stdin', '--auth-type=veracode_hmac',
                                       apiUrl],
                                      capture_output=True)
    print("The list of sandboxes have been retrieved")
    sandboxesJSON = json.loads(getSandboxesJSON.stdout)
    embeddedSandboxesDict = sandboxesJSON['_embedded']
    aSandboxList = embeddedSandboxesDict['sandboxes']
    print("The sandbox list has ", len(aSandboxList), "elements")
    mySandboxName = 'Eclipse'
    for sandbox in aSandboxList:
        if sandbox['name'] == mySandboxName:
            print("For sandbox name", mySandboxName, "The GUID is", sandbox['guid'])
            mySandboxGUID = sandbox['guid']
    return mySandboxGUID


def promoteBuild(appGUID, sandboxGUID):
    # For the given GUID, get a list of sandboxes
    apiUrl = "https://api.veracode.com/appsec/v1/applications/" + appGUID + "/sandboxes/" + sandboxGUID + "/promote"
    promoteBuildJSON = subprocess.run(['http', '--ignore-stdin', '--auth-type=veracode_hmac',
                                       'POST',
                                       apiUrl],
                                      capture_output=True)
    print("The list of sandboxes have been retrieved")
    promoteStdout = promoteBuildJSON.stdout
    promoteJSON = json.loads(promoteBuildJSON.stdout)
    iterate(promoteJSON)
    embeddedSandboxesDict = promoteJSON['_embedded']
    print(embeddedSandboxesDict.keys())
    iterate(embeddedSandboxesDict)
    pass


def main():
    appGUID = getApplicationGUID()

    sandboxGUID = getSandboxes(appGUID)

    promoteBuild(appGUID, sandboxGUID)


if __name__ == '__main__':
    main()