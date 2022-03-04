'''
For a specific application, retrieve the STATIC and/or SCA findings
For each of the findings, get the remediation recommendation string.


'''

import sys
import json
import http
import subprocess


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


def main():
    missingRecommendations = False
    appGUID = getApplicationGUID()

    findingList = getFindings(appGUID)
    if missingRecommendations:
        print("Note: some findings do not have recommendations.")


def getCWE(cwe):
    global missingRecommendations
    href = cwe.get('href')
    id = cwe.get('id')
    name = cwe.get('name')
    getCweJSON = subprocess.run(['http', '--ignore-stdin', '--auth-type=veracode_hmac',
                                            href],
                                            capture_output=True)
    cweJSON = json.loads(getCweJSON.stdout)
    # iterate(cweJSON)
    # print(cweJSON.keys())
    if 'recommendation' in cweJSON:
        recommendation = cweJSON.get('recommendation')
        if len(recommendation) == 0:
            print("For cwe", id, "(", name, ") there is no recommendation")
            missingRecommendations = True
        else:
            print("For cwe", id, "(", name, ")the recommendation is:")
            print(recommendation)


def getFindings(appGUID):
    # For the given GUID, retrieve the SCA findings
    global missingRecommendations
    aFindingsList = ""
    findingsURL = "https://api.veracode.com/appsec/v2/applications/" + appGUID + "/findings?scan_type=SCA"
    getFindingsJSON = subprocess.run(['http', '--ignore-stdin', '--auth-type=veracode_hmac',
                                      findingsURL],
                                     capture_output=True)
    print(findingsURL)
    findingsStdout = getFindingsJSON.stdout
    findingsStderr = getFindingsJSON.stderr
    if not len(findingsStdout):
        if "Request timed out" in findingsStderr.decode():
            print("There was an http error calling the findings API")
            print(findingsStderr.decode())
        else:
            print("There was an unknown error calling the findings API")
            print(findingsStderr.decode())
        return aFindingsList
    print("The list of findings for", appGUID, "have been retrieved")
    findingsJSON = {"_embedded": {"findings": "aFinding"}}
    try:
        findingsJSON = json.loads(findingsStdout)
    except json.JSONDecodeError as JSONDecodeError:
        print(JSONDecodeError)
    # iterate(findingsJSON)
    try:
        embeddedFindingsDict = findingsJSON['_embedded']
    except KeyError:
        print("This application has no SCA findings")
        return aFindingsList
    # iterate(embeddedFindingsDict)
    aFindingsList = embeddedFindingsDict['findings']
    print("The findings list has", len(aFindingsList), "element(s)")
    cweFindings = 0
    for finding in aFindingsList:
        findingDetails = finding['finding_details']
        # iterate(findingDetails)
        # See if this finding has a CWE object
        if 'cwe' in findingDetails:
            cweFindings += 1
            cwe = findingDetails.get('cwe')
            getCWE(cwe)
        else:
            pass
        if 'cve' in findingDetails:
            #print("True, contains a cve object")
            #cve = findingDetails.get('cve')
            #print(cve)
            pass
        else:
            pass
    print("There are", cweFindings, "SCA CWE findings for this application")
    return aFindingsList


def applicationMenu(anApplicationList):
    applicationName = ""
    appChoiceString = ("*" * 20) + " Menu " + ("*" * 20) + "\n\n"
    for index, application in enumerate(anApplicationList,1):
        appChoiceString += (" " * 16) + str(index) + ":\t" + application['guid'] + "\t" + application['profile']['name'] + "\n"
    appChoiceString += "            Please enter your choice: "
    choice = input(appChoiceString)
    try:
        print("Your choice is application", anApplicationList[int(choice)-1]['profile']['name'])
        applicationName = anApplicationList[int(choice)-1]['profile']['name']
    except ValueError:
        print("Your selection must be an integer")
    return applicationName


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
    myAppName = applicationMenu(anApplicationList)
    print("The selected application is", myAppName)
    for app in anApplicationList:
        appProfileName = app['profile']['name']
        if appProfileName == myAppName:
            print("For application name", appProfileName, "the GUID is", app['guid'])
            myAppGUID = app['guid']
    return myAppGUID


if __name__ == '__main__':
    main()