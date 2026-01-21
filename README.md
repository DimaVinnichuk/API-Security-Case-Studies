# API Security Findings

Real security issues I found during testing, sanitized to remove sensitive data.

## What's here

This repo contains write-ups of security vulnerabilities I discovered while testing APIs. All company names, endpoints, and specific data have been changed to protect confidentiality.

## Main Focus: BOLA Vulnerabilities

Most findings here are related to BOLA (Broken Object Level Authorization).

**What is BOLA?**

BOLA happens when an API doesn't properly check if you should have access to specific data. For example, if changing `/users/123` to `/users/456` lets you see someone else's information, that's BOLA.

In multi-tenant systems, this is especially critical because one company's users can access another company's data.

## Case Studies

Each case study in this repo includes:
- Description of the vulnerability
- How it was discovered
- Proof of concept with sanitized examples
- Impact assessment
- Lessons learned

Browse the `.md` files to see individual findings.

## How I Find Vulnerabilities

- Built a custom Python fuzzer to test API endpoints systematically
- Use OWASP ZAP for authentication and request analysis
- Test by manipulating parameters (IDs, tokens, etc.)
- Manually verify each finding
- Document everything properly

## What I've Learned

- Authentication doesn't mean authorization
- Multi-tenant apps need strict ownership checks on every object
- Never expose direct cloud storage URLs in API responses
- Sequential IDs make data enumeration easy
- Automated testing finds issues that manual testing misses
- One vulnerability often reveals patterns that lead to finding more

## Tools I Use

- Custom Python fuzzer (check my other repo: api-bola-fuzzer)
- OWASP ZAP
- Manual testing and validation

## Note

All issues were responsibly disclosed and have been fixed. This repo is for educational purposes and portfolio demonstration.
