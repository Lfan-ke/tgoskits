#!/bin/sh
# Start one process per ABI at the same time and let the scheduler have them.
# The shell loop is an ordinary ELF process, so all three ABIs are represented.
set -e
: > /tmp/abi-mix
{
    i=0
    # The shell has no yield, so a short sleep hands the processor on.
    while [ $i -lt 40 ]; do printf L; usleep 200 2>/dev/null || sleep 0; i=$((i + 1)); done
} >> /tmp/abi-mix &
elf_pid=$!
/usr/bin/interleave.exe >> /tmp/abi-mix &
pe_pid=$!
/usr/bin/interleave.macho >> /tmp/abi-mix &
macho_pid=$!
wait
echo
echo "MIX: $(cat /tmp/abi-mix)"
# One host, one identity allocator, three ABIs: the names it handed out have
# to be distinct however many ABIs are linked in.
echo "PIDS: $elf_pid $pe_pid $macho_pid"
distinct=$(printf '%s\n' "$elf_pid" "$pe_pid" "$macho_pid" | sort -u | wc -l)
[ "$distinct" -eq 3 ] || { echo "ABI-MIX-FAIL pids collided"; exit 1; }
# Each ABI has to have run, and the letters have to change hands - a single
# run of one letter would mean they ran one after another, not together.
for letter in L W M; do
    grep -q "$letter" /tmp/abi-mix || { echo "ABI-MIX-FAIL missing $letter"; exit 1; }
done
runs=$(cat /tmp/abi-mix | sed 's/\(.\)\1*/\1/g' | wc -c)
echo "RUNS: $runs"
[ "$runs" -ge 4 ] || { echo "ABI-MIX-FAIL no interleaving"; exit 1; }
echo ABI-MIX-OK
