# Norvion — SME Early-Warning System

**Version**: 1.0
**Status**: Production-ready with documented scale limitations

## Overview

Norvion is a deterministic, audit-first early-warning system for small and medium enterprises (SMEs). It analyzes uploaded transaction data using fixed, auditable rules to surface financial patterns and anomalies.

**What Norvion is:**
- Deterministic rule-based analysis
- Audit-first with stored evidence
- Informational only (not financial advice)
- User remains fully responsible for all decisions

**What Norvion is NOT:**
- NOT predictive or forward-looking
- NOT autonomous or AI/ML-driven
- NOT financial, investment, accounting, tax, or legal advice
- NOT a substitute for professional consultation

## Architecture and Scale Considerations

### Database: SQLite

**Current Implementation**: Norvion uses SQLite with WAL mode for data persistence.

**Suitable For:**
- Early-stage deployments
- Single-node installations
- Low-to-moderate concurrency (< 10 concurrent users)
- Small-to-medium tenant counts (< 100 tenants)
- Proof-of-concept and pilot deployments

**NOT Recommended For:**
- Large multi-tenant SaaS deployments
- High-concurrency environments (> 20 concurrent users)
- Distributed or multi-node architectures
- Mission-critical systems requiring HA/failover

**Migration Path**: For enterprise scale, a migration to PostgreSQL or MySQL is expected. The application architecture supports this transition with minimal refactoring (primarily connection string and query compatibility adjustments).

**Why SQLite Was Chosen:**
- Zero configuration for initial deployments
- Single-file database simplifies backups and portability
- Adequate performance for target SME use cases
- Reduces operational complexity for pilot customers

**When to Migrate:**
- Concurrent user count consistently exceeds 10
- Transaction volume requires horizontal scaling
- Tenant isolation requires separate database instances
- Enterprise SLAs demand failover and replication

### Data Encryption at Rest

#### Default Behavior

**SQLite does NOT encrypt data at rest by default.** The database file (`app.db`) and all stored transaction data are written to disk in plaintext unless the underlying storage is encrypted.

#### Operator Responsibility

Organizations deploying Norvion are **fully responsible** for encryption at rest. This includes:

**Infrastructure-Level Encryption** (Recommended):
- Encrypted disk volumes (LUKS on Linux, BitLocker on Windows, FileVault on macOS)
- Cloud provider encryption (AWS EBS encryption, Azure Disk Encryption, GCP persistent disk encryption)
- Storage array encryption (hardware-level encryption on enterprise storage systems)
- Filesystem-level encryption (eCryptfs, APFS encryption, ZFS encryption)

**Transport Encryption** (Required for Production):
- TLS/HTTPS termination at reverse proxy (nginx, Caddy, Traefik)
- Valid TLS certificates (Let's Encrypt, commercial CA)
- Modern cipher suites (TLS 1.2+ minimum, prefer TLS 1.3)

#### Norvion's Position

**Application-layer encryption is deliberately NOT implemented** to:
1. **Avoid security theater**: Encryption without proper key management provides false security
2. **Maintain operational transparency**: Operators must understand their security boundaries
3. **Enable infrastructure choice**: Organizations can use their existing encryption solutions
4. **Simplify compliance**: Encryption responsibility is explicit, not hidden

**This design assumes**:
- Infrastructure teams handle encryption at the appropriate layer (volume/disk level)
- Operators understand the security model before deploying
- Compliance requirements are met through infrastructure controls, not application features

#### Production Deployment Checklist

Before deploying with sensitive data, verify:

- [ ] Database file (`app.db`) resides on an encrypted volume
- [ ] Backup storage is encrypted (encrypted S3 buckets, encrypted backup volumes)
- [ ] TLS/HTTPS is enforced for all connections (no HTTP fallback)
- [ ] Session secrets are cryptographically random and stored securely
- [ ] Webhook secrets are cryptographically random and stored securely
- [ ] File permissions restrict database access to application user only (`chmod 600 app.db`)
- [ ] Infrastructure audit logs capture disk encryption status

#### Example Deployment Configurations

**Docker Deployment (AWS ECS with EBS encryption)**:
```
- EBS volume with encryption enabled (AWS-managed KMS key or custom CMK)
- Mount encrypted volume to container at /data
- Database path: /data/app.db
- TLS termination: AWS Application Load Balancer
```

**Bare Metal / VM (Linux with LUKS)**:
```
- LUKS-encrypted partition mounted at /var/norvion
- Database path: /var/norvion/app.db
- TLS termination: nginx reverse proxy with Let's Encrypt
- File permissions: chown norvion:norvion app.db && chmod 600 app.db
```

**Cloud VM (Azure with Managed Disk Encryption)**:
```
- Azure Managed Disk with encryption at rest enabled
- Mount disk to /mnt/norvion-data
- Database path: /mnt/norvion-data/app.db
- TLS termination: Azure Application Gateway or nginx
```

#### Why Not Application-Layer Encryption?

**Key Management Problem**: Application-layer encryption requires secure key storage. Common approaches:
- **Environment variables**: Keys visible in process listings, container configs
- **Config files**: Keys on disk, often in version control
- **Key management services**: Adds external dependencies, cost, complexity

**False Security**: Without proper key rotation, access controls, and audit trails, application-layer encryption provides minimal additional protection beyond infrastructure encryption.

**Operational Complexity**: Encrypted databases require key availability for every operation, complicating backups, restores, and disaster recovery.

**Recommendation**: Use infrastructure-level encryption with proper key management (AWS KMS, Azure Key Vault, HashiCorp Vault) rather than ad-hoc application encryption.

#### Compliance Notes

**GDPR (EU)**: Encryption at rest is recommended but not mandated. If processing sensitive personal data, encryption is expected as a "state of the art" technical measure.

**PCI DSS**: Requires encryption of cardholder data at rest (if applicable). Norvion does not process payment card data directly, but financial transaction metadata may require encryption depending on interpretation.

**HIPAA (US Healthcare)**: Requires encryption of ePHI at rest or documented risk acceptance. Not applicable unless Norvion is used for healthcare financial data.

**SOX (US Public Companies)**: Does not mandate encryption but requires documented controls for financial data integrity. Encryption supports control objectives.

**For Questions**: Consult security and compliance professionals for encryption requirements specific to your jurisdiction, industry, and data classification.

## Data Retention

### Default Behavior

**Data is retained indefinitely** unless explicitly deleted by an operator. This includes:
- Transaction data (uploaded CSV content)
- Run records (analysis snapshots)
- Alert records (triggered alerts and evidence)
- Alert state (user status updates and notes)
- Audit events (workflow history)
- User accounts and access logs

### Retention Policy Responsibility

**Operators are responsible** for defining and implementing retention policies appropriate to their:
- Regulatory environment (GDPR, CCPA, SOX, HIPAA, etc.)
- Business requirements (audit windows, compliance periods)
- Storage constraints (database size, backup costs)
- Contractual obligations (data processing agreements)

### Data Deletion Requirements

Any data deletion must be:
1. **Explicit**: No silent or automatic deletion
2. **Operator-initiated**: Requires admin action (direct database operation or future API)
3. **Logged**: All deletions must be recorded in audit logs
4. **Auditable**: Deletion records must be preserved according to compliance requirements
5. **Compliant**: Must meet applicable regulatory requirements (right to erasure, retention minimums, etc.)

### Current Implementation

- **No automated cleanup**: This version does not include scheduled data deletion
- **Manual database operations**: Admins can delete records via direct SQL (with full responsibility)
- **No built-in retention rules**: No age-based or count-based automatic deletion

### Recommended Practices

1. **Define retention periods** based on regulatory requirements (e.g., 7 years for financial records)
2. **Document retention policy** in your organization's data governance documentation
3. **Implement backup retention** aligned with operational recovery needs (e.g., 30-day rolling backups)
4. **Audit cleanup operations** and retain deletion logs according to compliance requirements
5. **Test restore procedures** to ensure compliance with retention obligations

### Future Enhancement

Configurable retention policies with deterministic, auditable cleanup logic may be added in future versions. Any future implementation will:
- Require explicit operator configuration (opt-in, never default)
- Provide full audit trails of deletions
- Support regulatory grace periods (e.g., "delete after X days, but preserve for Y days in archive")
- Maintain compliance with right-to-audit requirements

### Example Retention Scenarios

**Scenario 1: GDPR Compliance (EU)**
- Retain transaction data for 6 years (tax requirement)
- Delete user accounts 30 days after account closure request
- Preserve audit logs for 7 years

**Scenario 2: SOX Compliance (US Public Companies)**
- Retain financial records for 7 years minimum
- Preserve audit trails indefinitely
- Retain alert evidence for regulatory examination periods

**Scenario 3: SME Best Practice (No Specific Regulation)**
- Retain run history for 2-3 years (operational reference)
- Archive older runs to separate storage (cold storage)
- Delete test/demo data after pilot period ends

**For Questions**: Consult legal and compliance professionals for retention requirements specific to your jurisdiction and industry.

## Security and Access Control

### Authentication
- Role-based access control (RBAC): viewer, auditor, operator, manager, admin
- Session-based authentication with secure cookies
- CSRF protection on all state-changing operations

### Production Requirements
- `SME_EW_SESSION_SECRET` must be set to a cryptographically random value (NOT the demo default)
- `SME_EW_WEBHOOK_SECRET` must be set to a cryptographically random value (NOT the demo default)
- `SME_EW_ENV=production` must be set for production deployments
- Demo/dev routes are automatically disabled in production mode

### Terms of Service
- Users must accept TOS before accessing the system
- TOS version tracking per user
- Clear disclaimers about the informational nature of the tool

## Deployment Modes

### Development Mode
- `SME_EW_ENV=development` (default)
- Dev/test routes enabled (e.g., `/dev/generate-sample`)
- Relaxed validation for testing
- NOT suitable for production data

### Production Mode
- `SME_EW_ENV=production` (required)
- Dev/test routes return 404
- Strict secret validation (fails startup if insecure)
- Password reset disabled (admin-managed only)

## Multi-Tenancy

Norvion supports logical multi-tenancy:
- Tenant-scoped data isolation
- Tenant-specific categorization rules with fallback to default rules
- Settings can be tenant-scoped or global

**Limitation**: Shared SQLite database. For strict tenant isolation at scale, migrate to PostgreSQL with separate schemas or databases per tenant.

## Operational Warnings

1. **No Automatic Backups**: Operators must implement backup strategies (filesystem snapshots, volume backups, or `sqlite3` dump scripts).

2. **No Built-in Monitoring**: Integrate with external monitoring tools (Prometheus, Datadog, etc.) for production observability.

3. **No Built-in Alerting**: The system surfaces alerts to users; it does NOT send email/SMS notifications. Integrate with external notification systems if required.

4. **No High Availability**: Single-node SQLite architecture. For HA, migrate to a replicated database solution.

5. **No Horizontal Scaling**: Current architecture is vertically scalable only (increase CPU/RAM on single node).

## Support and Professional Consultation

**Important**: Norvion is an informational tool. Users are solely responsible for all business decisions made based on its output.

**Recommendations**:
- Consult qualified accountants for financial interpretation
- Consult legal professionals for compliance requirements
- Consult financial advisors for business strategy decisions

## License and Disclaimer

See Terms of Service (accessible at `/tos` when logged in) for complete legal disclaimers and limitations of liability.

**Summary**:
- Not financial advice
- Deterministic analysis only
- User remains fully responsible
- Verify with qualified professionals

---

**For technical support or enterprise inquiries**, contact the system administrator or deployment team.
