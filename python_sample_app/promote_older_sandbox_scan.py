'''
For a specific application, list the sandboxes for the application.
For each of the sandboxes, list the static scans.
Allow the user to select a static scan, and promote the scan to policy.

'''

import subprocess
import xml.etree.ElementTree as ET


def parseXML(xmlfile, name, id):
    # create element tree object
    tree = ET.parse(xmlfile)

    # get root element
    root = tree.getroot()

    # create empty dictionary for the children
    children = {}
    if len(list(root)) == 0 and root.tag == "error":
        # There are no child nodes
        print(root.tag, root.text)
    else:
        childList = list(tree.getroot())
        item: ET.Element
        for item in childList:
            children[item.attrib[name]] = item.attrib[id]

    # return children attributes
    return children


def getApplicationID():
    # Get a list of Applications
    getApplicationXML = subprocess.run(
        ['http', '--ignore-stdin', '--auth-type=veracode_hmac', 'https://analysiscenter.veracode.com/api/5.0/getapplist.do'],
        capture_output=True)

    # saving the xml file
    with open('applist.xml', 'wb') as f:
        f.write(getApplicationXML.stdout)

    applications = parseXML('applist.xml', 'app_name', 'app_id')
    myAppName = 'VerademoTF'
    print("For application name", myAppName, "The app_id is", applications[myAppName])
    myAppID = applications[myAppName]
    return myAppID


def getSandboxID(applicationID):
    sandboxURL = "https://analysiscenter.veracode.com/api/5.0/getsandboxlist.do app_id==" + applicationID
    getSandboxXML = subprocess.run(
        ['http', '--ignore-stdin', '--auth-type=veracode_hmac', 'https://analysiscenter.veracode.com/api/5.0/getsandboxlist.do', 'app_id==1203679'],
        capture_output=True)

    # saving the xml file
    with open('sandboxlist.xml', 'wb') as f:
        f.write(getSandboxXML.stdout)

    sandboxes = parseXML('sandboxlist.xml', 'sandbox_name', 'sandbox_id')
    mySandboxName = 'TeamCity'
    print("For Sandbox name", mySandboxName, "The sandbox_id is", sandboxes[mySandboxName])
    mySandboxID = sandboxes[mySandboxName]
    return mySandboxID


def getBuildsForSandbox(appID, sandboxID):
    # For the given sandbox, get a list of builds (scans)
    # http --auth-type=veracode_hmac "https://analysiscenter.veracode.com/api/5.0/getbuildlist.do" "app_id==<app id>" "sandbox_id==<sandbox id>"
    appIDParm = "app_id==" + appID
    sandboxIDParm = "sandbox_id==" + sandboxID
    apiUrl = "https://analysiscenter.veracode.com/api/5.0/getbuildlist.do " + appIDParm + sandboxIDParm
    getSandboxBuildXML = subprocess.run(['http', '--ignore-stdin', '--auth-type=veracode_hmac',
                                       'https://analysiscenter.veracode.com/api/5.0/getbuildlist.do', 'app_id==1203679', 'sandbox_id==3828266'],
                                      capture_output=True)

    # saving the xml file
    with open('sandboxbuildlist.xml', 'wb') as f:
        f.write(getSandboxBuildXML.stdout)

    builds = parseXML('sandboxbuildlist.xml', 'version', 'build_id')
    myBuildVersion = '14'
    print("For Build Version", myBuildVersion, "The build_id is", builds[myBuildVersion])
    myBuildID = builds[myBuildVersion]
    return myBuildID


def promoteBuild(buildID):
    # http --auth-type=veracode_hmac "https://analysiscenter.veracode.com/api/5.0/promotesandbox.do" "build_id==<build id>"
    promoteBuildXML = subprocess.run(
        ['http', '--ignore-stdin', '--auth-type=veracode_hmac', 'https://analysiscenter.veracode.com/api/5.0/promotesandbox.do', 'build_id==14141582'],
        capture_output=True)

    # saving the xml file
    with open('promotebuild.xml', 'wb') as f:
        f.write(promoteBuildXML.stdout)

    promotedBuild = parseXML('promotebuild.xml', 'version', 'build_id')
    if len(promotedBuild) > 0:
        print("The promoted build id is", promotedBuild.values())
        myBuildVersion = '14'
        print("For Build Version", myBuildVersion, "The build_id is", promotedBuild[myBuildVersion])
    else:
        print("The build 14141582 has not been promoted")


def main():

    applicationID = getApplicationID()

    sandboxID = getSandboxID(applicationID)

    buildID = getBuildsForSandbox(applicationID, sandboxID)
    
    promoteBuild(buildID)


if __name__ == '__main__':
    main()