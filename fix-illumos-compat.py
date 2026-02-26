#!/usr/bin/env python3
"""
fix-illumos-compat.py — Patch invoke-unix-forensics.sh for illumos/OpenIndiana

Fixes:
  1. Replace interactive `format` command with `iostat -En` (format hangs without tty)
  2. Fix `grep -c ... || echo "0"` double-zero bug (breaks bash arithmetic)
  3. Fix `wc -l ... || echo "0"` same pattern
  4. Fix `((count++))` returning exit 1 when count=0 (bash treats 0 as falsy)
  5. Skip CD-ROM devices in disk scanning loops
  6. Replace `sort -rh` with `sort -rn` (illumos sort lacks -h)
  7. Replace Linux netstat flags (-ant, -tuln) with illumos equivalents
  8. Fix colon-based port matching to dot-based for illumos netstat output

Usage:
  python3 fix-illumos-compat.py [path/to/invoke-unix-forensics.sh]

If no path given, defaults to invoke-unix-forensics.sh in the current directory.
"""

import re
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "invoke-unix-forensics.sh"

with open(target, "r") as f:
    content = f.read()

original = content
fixes = []

# ── 1. Replace interactive format with iostat -En ────────────────────────────

# 1a: analyze_disk_solaris — disk listing
old = (
    '    # Disk information\n'
    '    if command -v format >/dev/null 2>&1; then\n'
    '        echo "=== Disk Devices ===" | tee -a "$OUTPUT_FILE"\n'
    '        echo | format 2>/dev/null | grep "^[0-9]" | tee -a "$OUTPUT_FILE"\n'
    '        echo "" | tee -a "$OUTPUT_FILE"\n'
    '    fi'
)
new = (
    '    # Disk information (use iostat -En; interactive format hangs without a tty)\n'
    '    if command -v iostat >/dev/null 2>&1; then\n'
    '        echo "=== Disk Devices ===" | tee -a "$OUTPUT_FILE"\n'
    '        iostat -En 2>/dev/null | tee -a "$OUTPUT_FILE"\n'
    '        echo "" | tee -a "$OUTPUT_FILE"\n'
    '    fi'
)
if old in content:
    content = content.replace(old, new, 1)
    fixes.append("1a: Replaced format with iostat -En in analyze_disk_solaris")

# 1b: analyze_storage_profile — disk_list builder
old = '        local disk_list=$(echo "" | format 2>/dev/null | grep "^[[:space:]]*[0-9]" | awk \'{print $2}\')'
new = (
    '        local disk_list=""\n'
    '        for _d in $(iostat -En 2>/dev/null | awk \'/^c[0-9]/{print $1}\'); do\n'
    '            iostat -En "$_d" 2>/dev/null | grep -qi "CD-ROM" && continue\n'
    '            disk_list="$disk_list $_d"\n'
    '        done'
)
if old in content:
    content = content.replace(old, new, 1)
    fixes.append("1b: Replaced format disk_list with iostat -En + CD-ROM filter")

# 1c: storage topology — format listing
old = '        echo "" | format 2>/dev/null | egrep "^[0-9]|c[0-9]" | tee -a "$OUTPUT_FILE"'
new = '        iostat -En 2>/dev/null | egrep "^c[0-9]|Size:|Vendor:" | tee -a "$OUTPUT_FILE"'
if old in content:
    content = content.replace(old, new, 1)
    fixes.append("1c: Replaced format in storage topology with iostat -En")

# ── 2. Fix grep -c ... || echo "0" ──────────────────────────────────────────
count = content.count('|| echo "0")')
if count > 0:
    content = content.replace('|| echo "0")', '|| true)')
    fixes.append(f'2: Fixed || echo "0" -> || true ({count} instances)')

# ── 3. Fix ((count++)) when count=0 ─────────────────────────────────────────
plusplus = re.findall(r'\(\((\w+)\+\+\)\)', content)
for var in sorted(set(plusplus)):
    old_inc = f'(({var}++))'
    new_inc = f'{var}=$(({var} + 1))'
    n = content.count(old_inc)
    if n > 0:
        content = content.replace(old_inc, new_inc)
        fixes.append(f"3: Fixed (({var}++)) -> safe increment ({n} instances)")

# ── 4. Skip CD-ROM in /dev/rdsk loops ───────────────────────────────────────
old_guard = (
    '            [[ -c "$disk_dev" ]] || continue\n'
    '            \n'
    '            local disk_base=$(basename "$disk_dev" | sed \'s/s2$//\')'
)
new_guard = (
    '            [[ -c "$disk_dev" ]] || continue\n'
    '\n'
    '            local disk_base=$(basename "$disk_dev" | sed \'s/s2$//\')\n'
    '            # Skip CD-ROM / non-disk devices\n'
    '            iostat -En "$disk_base" 2>/dev/null | grep -qi "CD-ROM" && continue'
)
if old_guard in content:
    content = content.replace(old_guard, new_guard)
    fixes.append("4: Added CD-ROM skip to partition alignment loop")

# ── 5. Replace sort -rh with sort -rn ───────────────────────────────────────
old_sort = 'du -sh /* 2>/dev/null | sort -rh | head -10'
new_sort = 'du -sk /* 2>/dev/null | sort -rn | head -10'
if old_sort in content:
    content = content.replace(old_sort, new_sort)
    fixes.append("5: Replaced sort -rh -> sort -rn, du -sh -> du -sk")

# ── 6. Replace Linux netstat flags with illumos equivalents ──────────────────
n1 = content.count('netstat -ant 2>/dev/null')
if n1:
    content = content.replace('netstat -ant 2>/dev/null', 'netstat -an -f inet -P tcp 2>/dev/null')
    fixes.append(f"6a: Fixed netstat -ant -> -an -f inet -P tcp ({n1} instances)")

n2 = content.count('netstat -tuln 2>/dev/null')
if n2:
    content = content.replace('netstat -tuln 2>/dev/null', 'netstat -an -f inet 2>/dev/null')
    fixes.append(f"6b: Fixed netstat -tuln -> -an -f inet ({n2} instances)")

# ── 7. Fix colon-based port matching for illumos netstat output ──────────────
#    Linux netstat: 10.0.2.15:22     illumos netstat: 10.0.2.15.22
def fix_port_grep(m):
    port = m.group(1)
    return f'grep "[.]{port}[[:space:]]"'

new_content = re.sub(r'grep ":(\d+)"', fix_port_grep, content)
if new_content != content:
    content = new_content
    fixes.append("7a: Fixed grep :PORT -> grep [.]PORT for illumos netstat")

# Also fix compound egrep port patterns
old_egrep = 'egrep ":3306|:5432|:1521|:1433|:27017"'
new_egrep = 'egrep "[.]3306[[:space:]]|[.]5432[[:space:]]|[.]1521[[:space:]]|[.]1433[[:space:]]|[.]27017[[:space:]]"'
if old_egrep in content:
    content = content.replace(old_egrep, new_egrep)
    fixes.append("7b: Fixed egrep compound port pattern for illumos")

# ── Write ────────────────────────────────────────────────────────────────────
if content == original:
    print("No changes needed — script is already patched.")
    sys.exit(0)

with open(target, "w") as f:
    f.write(content)

print(f"Applied {len(fixes)} fix(es) to {target}:\n")
for f in fixes:
    print(f"  {f}")
