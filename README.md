# URLRequest+AWS

An extension on `URLRequest` to sign it for AWS.

## Example Usage

```swift
var request = URLRequest(url: URL(string: "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08")!)

request.sign(credentials: credentials, date: date, region: "us-east-1", service: "iam")
```
