# Changelog

## 1.0.1

- Fixed unique resource counting for mv-expand collectors (NSG, VNet, RouteTable, RouteFilter, Peering)
- Fixed SQLFirewall, MySQLConfig, PostgreSQLConfig UniqueField to count parent servers not child entries
- Fixed Peerings collector missing localSubscriptionId and remoteSubscriptionId
- Fixed Tags collector missing tagCount and excluding untagged resources
- Added vault scope to Connect-ArSession (all auth upfront)
- Added permission pre-flight checks before collection
- Export purges default output directory on each run
- Invoke-ArAudit opens HTML report automatically
- All output to %TEMP%/NCS/AzResourceAnalyzer by default

## 1.0.0

- Initial release
- 70 auto-discovered resource collectors
- 269 checks across 7 CIS benchmark sections
- Device code authentication with SecureString token storage
- Tab completion for -Collector parameter
- HTML report with NCS Dojo branding
- Session-gated commands
