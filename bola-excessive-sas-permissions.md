# Broken Object Level Authorization and Excessive SAS Permissions

## Summary
Unauthorized users can access an admin-only API object that exposes an Azure Blob Storage SAS URL, allowing them to read and overwrite sensitive license documents.

## Severity
CVSS 3.1 Score: 8.6 (High)

**Justification:** 
- Broken Object Level Authorization (BOLA) allows access to an admin-only API object
- The API response exposes Azure Blob Storage SAS URLs with read and write permissions
- Enables unauthorized access, modification, and replacement of official license documents
- Affects business-critical and compliance-relevant data
- Can lead to fraud, legal exposure, and loss of data integrity
- Attack complexity is low and requires only a regular authenticated user
- No additional privileges or user interaction are required 

Despite requiring authentication, this vulnerability enables full compromise of sensitive documents across tenants, making the real-world impact high.

## Application Context

- **Architecture**: Multi-tenant SaaS
- **Authentication**: Required valid user session
- **Authorization model**: Role-based and tenant-based access control (admin-only license endpoints)
- **Sensitive data involved**: Business license documents, contractual records, and associated metadata

## Affected Endpoint
```http
GET /api/v1/licenses/{tenantId}
```
**Intended behavior**: The license endpoint should return license objects only to authorized administrative users.

## Vulnerability Description

The license API endpoint verifies that the requester is authenticated but fails to enforce object-level and role-based authorization. This behavior was confirmed across multiple ``tenantId`` values, indicating a systemic cross-tenant authorization flaw.

By modifying the ``tenantId`` parameter, an authenticated non-admin user can retrieve admin-only license objects belonging to other tenants.
These objects expose Azure Blob Storage SAS URLs with excessive permissions (read/write) to license documents, allowing the attacker to directly read and overwrite sensitive files stored in Blob Storage.



## Proof of Concept

### Testing Methodology

- A custom Python script was used to systematically test API endpoints and identify suspicious authorization behaviors
- OWASP ZAP was configured as an intercepting proxy to provide automatic authentication, session handling, and traffic inspection during testing
- Identified endpoints were further analyzed by fuzzing path parameters in OWASP ZAP to confirm unauthorized access to objects belonging to other tenants
- All findings were manually validated by reviewing requests and responses in OWASP ZAP
- The exposed Azure Blob Storage access was then manually verified to confirm unauthorized reading and overwriting of documents

### Exploitation Steps

Step 1: API request to retrieve a license object exposing a document path. 

```http
GET https://api.example.com/api/v1/licenses/123 HTTP/1.1
host: api.example.com

------

HTTP/1.1 200 OK

{"id":123,"salesPerson":"Employee A","purchaseDate":"YYYY-MM-DD","expiryDate":"YYYY-MM-DD","licenseAgreementId":456,"description":"Sample license record","documentPath":"https://storage.examplecloud.net/tenant-123/licenses/agreement-456.pdf?<SAS_TOKEN_REDACTED>","status":1,"tenantId":123,"licenseMonth":"MM","applicationId":789,"createdBy":42,"createdOn":"YYYY-MM-DDTHH:MM:SS","modifiedBy":42,"modifiedOn":"YYYY-MM-DDTHH:MM:SS","licenseCategoryId":null,"pricePerMonth":null}

# <SAS_TOKEN_REDACTED> = a valid Azure Blob Storage SAS token returned by the vulnerable API
# Unauthorized access
```

Step 2: Direct request to blob storage via an exposed SAS token

```http
GET https://storage.examplecloud.net/tenant-123/licenses/agreement-456.pdf?<SAS_TOKEN_REDACTED> HTTP/1.1
host: storage.examplecloud.net

------

HTTP/1.1 200 OK
[BINARY_DOCUMENT_CONTENT]

# Unauthorized access to read the document
```

Step 3: PUT request to the exposed SAS URI, allowing upload of a malicious payload.
```http
PUT https://storage.examplecloud.net/tenant-123/licenses/agreement-456.pdf?<SAS_TOKEN_REDACTED> HTTP/1.1
host: storage.examplecloud.net
x-ms-blob-type: BlockBlob

MALICIOUS_BODY_PAYLOAD

------

HTTP/1.1 201 Created

# Unauthorized access to write the document
```

### Impact Metrics

- **Testing sample**: 501 ``tenantId`` values tested (range: 0-500)
- **Vulnerable records**:

    - 64 returned 200 OK and exposed license data including the SalesPerson field (personal name)
    - 6 of those exposed a DocumentPath containing a SAS URL with read/write permissions
- Enumeration feasibility: High (sequential and predictable ``tenantId`` values)
- Access level obtained: Read and write access to Azure Blob Storage for exposed documents

### Impact

- Unauthorized cross-tenant access to license records
- Exposure of personally identifiable information (PII) through the SalesPerson field
- Disclosure of direct storage access URLs to official license documents
- Ability to download, modify, or replace documents stored in Azure Blob Storage
- Risk of fraud, document tampering, and loss of data integrity
- Enables large-scale enumeration of tenant data via predictable ``tenantId`` values 

In a multi-tenant SaaS environment, this allows any authenticated user to access and manipulate data and documents belonging to other businesses, resulting in serious confidentiality and integrity violations.

### Root Cause Analysis

- Authorization logic was fragmented and non-centralized across the codebase
- Authentication was enforced, but tenant ownership and admin-role checks were incomplete or missing at the object level
- Azure Blob Storage access is exposed via SAS URLs in API responses, replacing server-side authorization with client-side SAS-based access
- SAS tokens grant excessive read/write permissions, amplifying the impact of the vulnerability

### Recommended Remediation

- Enforce strict tenant ownership and admin-role validation for all license objects at the API level
- Centralize authorization logic to ensure consistent enforcement across the codebase
- Do not expose direct storage URLs (SAS tokens) to client-side users; serve documents through server-mediated access
- Limit SAS token permissions to the minimum required (read-only if possible) and reduce token lifetime
- Add automated negative authorization tests for cross-tenant access scenarios
- Treat all object identifiers as untrusted user input
- Integrate automated authorization testing into the CI/CD pipeline to catch regressions

