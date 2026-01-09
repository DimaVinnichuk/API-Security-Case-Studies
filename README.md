# Security Case Studies

This repository contains sanitized and anonymized application security case studies based on real-world issues identified during an internship.

## Contents
- Broken Object Level Authorization (BOLA) in a Multi-Tenant SaaS API:
  - Issue: Unauthorized cross-tenant access to contact records due to inconsistent object-level authorization.
  - Impact: Exposure of PII and potential for large-scale data enumeration.
  - OWASP API Top 10: Broken Object Level Authorization.

- BOLA and Excessive SAS Permissions:
  - Issue: Unauthorized access to admin-only license objects exposing Azure Blob Storage SAS URLs.
  - Impact: Ability to read, modify, or replace sensitive business documents across tenants.
  - OWASP API Top 10: Broken Object Level Authorization.