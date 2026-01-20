# Broken Object Level Authorization. Excessive SAS Permissions. Personally Identifiable Information exposure

## Summary
Unauthorized users can access objects from other tenants that expose an Azure Blob Storage SAS URL, allowing reading and overwriting of hosted files. One of the affected endpoints also leaks employees' Personally Identifiable Information (PII) along with SAS URLs for personal documents with full read and write permissions.

## Severity
CVSS v4.0 Score: 8.4 / High

**Justification**:
- The API response exposes Azure Blob Storage SAS URLs with excessive read and write permissions.
- Enables unauthorized access, modification, and replacement of hosted files.
- Exposes employees' PII, leading to privacy breaches and regulatory non-compliance.
- Affects business-critical and compliance-relevant data stored within the cloud infrastructure.
- Can lead to fraud, legal exposure, and a total loss of data integrity due to unauthorized file overwriting.
- Attack complexity is low and does not require any additional privileges or user interaction.

## Application Context
- **Architecture**: Multi-tenant SaaS.
- **Authentication**: Required valid user session.
- **Authorization model**: Role-based and tenant-based access control.
- **Sensitive data involved**: Personally Identifiable Information, employment details, business data, personal employee documents.

## Affected Endpoints
```http
GET /api/hrm/v1/staff/{staffId}/documents/{organizationId}/{unitId}/{documentType} - get documents for all staff members in an organization or unit.

GET /api/platform/v1/tenant/{tenantId} - retrieve a single tenant by its tenantId

GET /api/forms/v1/submission/{submissionId} - retrieve submission details based on the provided submission ID
```

## Vulnerability Description
The API endpoints ``/api/hrm/v1/staff/{staffId}/documents/{organizationId}/{unitId}/{documentType}`` and ``/api/forms/v1/submission/{submissionId}`` verify that the requester is authenticated but fail to enforce proper object-level (BOLA) and role-based (RBAC) authorization. This behavior was confirmed across multiple ``organizationId`` and ``submissionId`` values, indicating a systemic cross-tenant authorization flaw.

Additionally, the endpoint ``/api/platform/v1/tenant/{tenantId}`` was found to be vulnerable. While most requests return a 403 Forbidden status, an authenticated user can successfully retrieve sensitive objects by targeting specific identifiers, such as ``tenantId``: 1.

## Proof of Concept

### Testing Methodology

- A custom Python script was used to systematically test API endpoints and identify suspicious authorization behaviors
- OWASP ZAP was configured as an intercepting proxy to provide automatic authentication, session handling, and traffic inspection during testing
- Identified endpoints were further analyzed by fuzzing path parameters in OWASP ZAP to confirm unauthorized access to objects belonging to other tenants
- All findings were manually validated by reviewing requests and responses in OWASP ZAP

## Exploitation steps

1. **Vulnerable Endpoint**: ``GET /api/hrm/v1/staff/{staffId}/documents/{organizationId}/{unitId}/{documentType}``
```http
# Requesting the endpoint to retrieve documents for all staff members in an organization or unit

GET https://api.example-company.com/api/hrm/v1/staff/2/documents/53/2/2 HTTP/1.1
host: api.example-company.com

HTTP/1.1 200 OK
[
    {"StaffId":60386,"StaffName":"Alice Johnson",
    "EmploymentType":"Full-time","OrganizationName":"Tech Solutions Inc",
    "UnitName":"Engineering Division","OrganizationUnitIds":[17445]},
    {"StaffId":54372,"StaffName":"Bob Smith",
    "TotalDocuments":4,"TotalApprovedDocuments":0,
    "StaffDocuments":[{"Id":55160,
    "Filename":"safety-certification.pdf","Mimetype":"application/pdf","Size":1341012,
    "Path":"https://examplestorage.blob.core.windows.net/tenant-alpha/org-53/staff-54372/safety-certification-20231103105601579.pdf?sv=2023-11-03&st=2026-01-19T07%3A28%3A58Z&se=2026-01-19T08%3A33%3A58Z&sr=b&sp=rw&sig=REDACTED_SIGNATURE_TOKEN_12345"
        ... }]}
]

# Exposure Azure Blob Storage SAS URL, allowing reading and overwriting of hosted files. PII. Business data
```

2. **Vulnerable Endpoint**: ``GET /api/platform/v1/tenant/{tenantId}``
```http
# Requesting the endpoint to retrieve a single tenant by using the tenantId parameter value of 1

GET https://api.example-company.com/api/platform/v1/tenant/1 HTTP/1.1
host: api.example-company.com

HTTP/1.1 200 OK
{
    ...
    "LogoPath":"https://examplestorage.blob.core.windows.net/tenant-alpha/tenant-1/assets/company-logo.jpg?sv=2023-11-03&st=2026-01-19T08%3A29%3A51Z&se=2026-01-19T09%3A34%3A51Z&sr=b&sp=rw&sig=REDACTED_SIGNATURE_TOKEN_67890", 
    ...
}

# Exposure Azure Blob Storage SAS URL, allowing for the reading and overwriting of hosted file
```

3. **Vulnerable endpoint**: ``GET /api/forms/v1/submission/{submissionId}``
```http
# Requesting the endpoint to retrieve submission details

GET https://api.example-company.com/api/forms/v1/submission/54 HTTP/1.1
host: api.example-company.com

HTTP/1.1 200 OK
{
    ...
    "Path":"https://examplestorage.blob.core.windows.net/tenant-beta/org-612/category-5/submissions-171/attachment-20160330.jpg?sv=2023-11-03&st=2026-01-19T09%3A26%3A14Z&se=2026-01-19T10%3A31%3A14Z&sr=b&sp=rw&sig=REDACTED_SIGNATURE_TOKEN_ABCDE",
    "CreatedOn":"2016-03-30T13:07:51.88",
    "CreatorName":"John Doe"
    ...
}

# Exposure Azure Blob Storage SAS URL, allowing for the reading and overwriting of hosted file
```

### Impact
The identified Broken Object Level Authorization (BOLA) vulnerability poses a significant risk to data confidentiality and multi-tenant isolation. By manipulating ID parameters, an attacker can achieve:
- Data Integrity and Ransomware Risk: The exposure of SAS tokens with write permissions allows an attacker to delete, corrupt, or overwrite business-critical files and employee documents. This could be used to inject malicious files or perform a ransomware-style attack by encrypting/deleting hosted data.
- Unauthorized Data Disclosure: Access to sensitive Personally Identifiable Information, including full names, employment details, and private documents such as educational diplomas.
- Multi-tenancy Breach: Complete bypass of tenant boundaries, allowing one client to view another client's private project details.
- Regulatory Non-compliance: Direct violation of GDPR and data protection laws due to the exposure of personal and business-sensitive data.
- Data Scraping: The use of sequential integer IDs enables automated mass extraction of the entire database via simple enumeration.

### Root Cause Analysis
- Missing Tenant Validation: Authentication exists, but the system fails to verify resource ownership (tenant-to-object mapping).
- Decentralized Authorization: Security checks are likely inconsistent across the codebase rather than managed by a central, unified authorization service.
- Sequential Integer IDs: The use of predictable, sequential integers allows for easy data enumeration and mass scraping (IDOR).
- Input Over-trust: Server-side logic trusts user-supplied IDs without cross-referencing them against the authenticated user's session context and tenant scope.
- Insecure Token Generation (Least Privilege Violation): The system generates Azure Blob Storage SAS URLs with broad Read/Write permissions by default, rather than limiting scope to Read-only for specific requested resources.

### Recommended Remediation
- Enforce strict tenant ownership validation for all object-level access
- Centralize authorization logic to ensure consistent enforcement
- Treat object identifiers as untrusted user input
- Integrate negative authorization tests into the CI/CD pipeline to detect cross-tenant access attempts before deployment
- Do not expose direct storage URLs (SAS tokens) to client-side users; serve documents through server-mediated access