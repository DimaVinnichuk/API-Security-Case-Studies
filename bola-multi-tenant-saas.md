# Broken Object Level Authorization in Multi-Tenant SaaS API

> This is a sanitized and anonymized case study based on a real-world issue discovered during an internship.
> All identifiers, endpoints, and data structures have been modified to prevent disclosure of sensitive or proprietary information.

## Summary
During an application security assessment of a multi-tenant SaaS platform, a Broken Object Level Authorization (BOLA) vulnerability was identified in an API endpoint responsible for retrieving contact records. The issue allowed authenticated users to access contact information belonging to other tenants by manipulating object identifiers.

## Severity: High

**CVSS 3.1 Score:** 6.5 (Medium)

**Justification:**
- Broken Object Level Authorization (BOLA) in a multi-tenant SaaS
- Unauthorized cross-tenant access to sensitive data
- Exposure of personally identifiable information (PII)
- Low attack complexity, requiring only an authenticated user
- High business impact due to violation of tenant isolation and compliance requirements

Despite the Medium CVSS score, this vulnerability is considered **high-risk** in the context of a multi-tenant SaaS platform.

## Application Context
- **Architecture:** Multi-tenant SaaS
- **Authentication:** Required (valid user session)
- **Authorization model:** Tenant-based access control
- **Sensitive data involved:** Contact information (PII)

## Affected Endpoint (Anonymized)
```http
GET /api/contact/{id}
```
    
**Intended behavior:** Return contact details only if the requested contact belongs to the same tenant as the authenticated user.

## Vulnerability Description
The endpoint validated that the requester was authenticated but failed to consistently enforce object-level authorization.

By modifying the `id` path parameter, an authenticated user could retrieve contact records associated with other tenants.

### Inconsistent Authorization Behavior
Some object identifiers were correctly restricted, while others returned unauthorized data, indicating **inconsistent authorization checks** across different code paths or data states.

## Proof of Concept (Sanitized)

### Testing Methodology
- Manual API testing using OWASP ZAP
- Sequential ID enumeration
- Cross-tenant access validation
- Authorization boundary testing

### Exploitation Steps
```http
# Step 1: Requesting a contact belonging to the user's own tenant
GET /api/contact/225 HTTP/1.1
Host: api.example.com

HTTP/1.1 200 OK
{
    "id": 225,
    "name": "John Doe",
    "email": "john@company-a.com",
    "tenant_id": "tenant_a"
}
# Expected behavior
```

```http
# Step 2: Requesting a contact belonging to a different tenant
GET /api/contact/388 HTTP/1.1
Host: api.example.com

HTTP/1.1 200 OK
{
    "id": 388,
    "name": "Jane Smith",
    "email": "jane@company-b.com",
    "tenant_id": "tenant_b" # Different tenant!
}
# Unauthorized access (vulnerability)
```

```http
# Step 3: Requesting another contact belonging to a different tenant
GET /api/contact/455 HTTP/1.1
Host: api.example.com

HTTP/1.1 403 Forbidden
# Properly restricted
```
Some object identifiers correctly returned 403 Forbidden, while others returned 200 OK with unauthorized data. This indicates **inconsistent enforcement of tenant ownership checks**.

## Impact Metrics
- Testing sample: 500 IDs tested (range: 1-500)
- Vulnerable records: 234 returned unauthorized data (46.8%)
- Enumeration feasibility: High (sequential IDs)

## Impact
- Unauthorized cross-tenant access to contact information
- Potential exposure of personally identifiable information (PII), including:
    - Names
    - Email addresses
    - Associated company names
- Risk of large-scale data enumeration through object ID manipulation

In a multi-tenant SaaS environment, this issue could lead to serious confidentiality violations between business customers.

## Root Cause Analysis
- Authorization logic was applied inconsistently at the object level
- Authentication was enforced, but tenant ownership checks were missing or fragmented
- Suggests that authorization was implemented in a non-centralized manner across the codebase

## Recommended Remediation
- Enforce strict tenant ownership validation for all object-level access
- Centralize authorization logic to ensure consistent enforcement
- Add automated negative authorization tests for cross-tenant access scenarios
- Treat object identifiers as untrusted user input
- Integrate automated authorization testing into CI/CD pipeline

## Lessons Learned
- Authentication alone does not prevent unauthorized access
- Object identifiers do not provide security guarantees
- Multi-tenant applications require strict object-level authorization checks
- Automated API testing should explicitly cover authorization boundaries

## Status
The issue was responsibly disclosed internally and has since been remediated. 