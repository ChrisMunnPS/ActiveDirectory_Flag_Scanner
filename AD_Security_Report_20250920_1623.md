# AD Security Audit Report

**Generated:** 2025-09-20 16:23:43  
**Domain:** Homelan.lab  

## Summary
- **Flagged Accounts:** 7
- **Privileged Users:** 4  
- **High Risk Flags:** 2
- **Critical Groups:** 3
- **Stale Accounts:** 4

## Account Control Flags
| Flag | Risk | Count | Description |
|------|------|-------|-------------|| DONT_REQ_PREAUTH | High | 1 | No Kerberos PreAuth required |
| DontExpirePassword | Medium | 3 | Password never expires |
| AccountDisabled | Low | 2 | Disabled accounts |
| PasswordCantChange | Medium | 0 | Password cannot change |
| Lockout | Medium | 0 | Locked-out accounts |
| UseDesKey | High | 0 | Use DES encryption (weak) |
| PasswordNotRequired | High | 1 | Password not required |
| TrustedForDelegation | High | 0 | Trusted for delegation |

## Privileged Groups
| Group | Risk | Enabled | Description |
|-------|------|---------|-------------|| Account Operators | High | 0 | User/Group management |
| Enterprise Admins | Critical | 1 | Full forest control |
| Schema Admins | Critical | 1 | Schema modification rights |
| Domain Admins | Critical | 1 | Full domain control |
| Server Operators | High | 0 | Server management |
| Administrators | High | 1 | Local admin rights |
| DNSAdmins | High | 0 | DNS management |
| Backup Operators | High | 0 | Backup/Restore privileges |
| Print Operators | Medium | 0 | Printer management |

## Alerts
- ⚠️ Stale accounts detected: 4 accounts
- 🔴 Critical groups with members: 3 groups need review

