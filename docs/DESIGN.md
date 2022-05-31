# DESIGN

## Reload Configuration file

### Limitation - Unsupport configurations
1. Listen section: Server/Admin
2. Cache section

### Support
1. add/delete nameserver
2. add/delete view/hosts rules
3. add/delete black/white list

## Cache

### memory usage
1. global memory usage
    * runtime.ReadMemStats(m *MemStats)
