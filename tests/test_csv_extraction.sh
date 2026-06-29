#!/bin/bash
################################################################################
# Test script: validates that csv_to_tsv + the main loop extract exactly 150
# rows with correct CWE IDs and prompts — same logic as Run_with_dataset.sh.
################################################################################

DATASET_PATH="LLMSecEval/LLMSecEval-Prompts_dataset.csv"
C_ONLY_CWES="CWE-119 CWE-125 CWE-190 CWE-416 CWE-476 CWE-787"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# --- Same helper functions as Run_with_dataset.sh ---

extract_cwe_from_prompt_id() {
    local prompt_id="$1"

    if [[ "$prompt_id" =~ CWE-([0-9]+) ]]; then
        local cwe_num="${BASH_REMATCH[1]}"
        cwe_num=$((10#$cwe_num))
        echo "CWE-${cwe_num}"
        return 0
    fi

    if [[ "$prompt_id" =~ cwe[_-]?([0-9]+) ]]; then
        local cwe_num="${BASH_REMATCH[1]}"
        cwe_num=$((10#$cwe_num))
        echo "CWE-${cwe_num}"
        return 0
    fi

    echo ""
    return 1
}

is_c_only_cwe() {
    local cwe="$1"
    for c in $C_ONLY_CWES; do
        [ "$c" = "$cwe" ] && return 0
    done
    return 1
}

csv_to_tsv() {
    python3 -c "
import csv, sys
reader = csv.reader(open(sys.argv[1], newline=''))
next(reader)  # skip header
for row in reader:
    if len(row) >= 5:
        # Replace embedded newlines with spaces so bash read gets one line per row
        clean = [field.replace('\n', ' ').replace('\r', ' ') for field in row[:5]]
        print('\t'.join(clean))
" "$1"
}

# --- Main test ---

echo "=========================================="
echo "  CSV Extraction Test"
echo "=========================================="
echo ""

if [ ! -f "$DATASET_PATH" ]; then
    echo -e "${RED}[FAIL]${NC} Dataset not found: $DATASET_PATH"
    exit 1
fi

line_num=0
total=0
skipped_no_cwe=0
skipped_no_prompt=0
skipped_empty_id=0

declare -A cwe_counts
declare -A lang_counts

while IFS=$'\t' read -r prompt_id cwe_col nl_prompt filename lang_raw; do
    line_num=$((line_num + 1))
    data_idx=$((line_num - 1))

    # Strip quotes (defensive, same as Run_with_dataset.sh)
    prompt_id=$(echo "$prompt_id" | tr -d '"')
    cwe_col=$(echo "$cwe_col"     | tr -d '"')
    nl_prompt=$(echo "$nl_prompt" | tr -d '"')

    # Normalise language
    case "$(echo "$lang_raw" | tr -d '"' | tr -d ' ' | tr '[:upper:]' '[:lower:]')" in
        c)          lang="C" ;;
        c++|cpp)    lang="C++" ;;
        python|py)  lang="Python" ;;
        java)       lang="Java" ;;
        javascript|js) lang="JavaScript" ;;
        *)          lang="${lang_raw:-C}" ;;
    esac

    [ -z "$prompt_id" ] && { skipped_empty_id=$((skipped_empty_id + 1)); continue; }

    # Resolve CWE
    cwe=""
    [ -n "$cwe_col" ] && cwe=$(extract_cwe_from_prompt_id "$cwe_col")
    [ -z "$cwe" ]     && cwe=$(extract_cwe_from_prompt_id "$prompt_id")
    if [ -z "$cwe" ]; then
        skipped_no_cwe=$((skipped_no_cwe + 1))
        echo -e "${YELLOW}[SKIP]${NC} Row $data_idx ($prompt_id): no CWE found"
        continue
    fi

    # Language override for non-C-only CWEs (same logic as Run_with_dataset.sh)
    if [ "$lang" = "C" ] || [ "$lang" = "C++" ]; then
        if is_c_only_cwe "$cwe"; then
            lang="$lang"  # keep C
        else
            lang="Python" # override
        fi
    fi

    # Substitute <language> placeholder
    nl_prompt="${nl_prompt//<language>/$lang}"
    nl_prompt="${nl_prompt//<lanuage>/$lang}"

    if [ -z "$nl_prompt" ]; then
        skipped_no_prompt=$((skipped_no_prompt + 1))
        echo -e "${YELLOW}[SKIP]${NC} Row $data_idx ($prompt_id): empty prompt"
        continue
    fi

    total=$((total + 1))
    cwe_counts[$cwe]=$(( ${cwe_counts[$cwe]:-0} + 1 ))
    lang_counts[$lang]=$(( ${lang_counts[$lang]:-0} + 1 ))

    # Print each extracted row
    printf "${GREEN}[%3d]${NC} Row %-3d | %-20s | %-8s | %-6s | %.70s\n" \
        "$total" "$data_idx" "$prompt_id" "$cwe" "$lang" "$nl_prompt"

done < <(csv_to_tsv "$DATASET_PATH")

echo ""
echo "=========================================="
echo "  RESULTS"
echo "=========================================="
echo "  Total rows from csv_to_tsv : $line_num"
echo "  Valid prompts extracted     : $total"
echo "  Skipped (empty ID)         : $skipped_empty_id"
echo "  Skipped (no CWE)           : $skipped_no_cwe"
echo "  Skipped (empty prompt)     : $skipped_no_prompt"
echo ""

# Verify count
if [ "$total" -eq 150 ]; then
    echo -e "  ${GREEN}[PASS]${NC} Exactly 150 prompts extracted"
elif [ "$total" -lt 150 ]; then
    echo -e "  ${RED}[FAIL]${NC} Only $total prompts (expected 150)"
else
    echo -e "  ${RED}[FAIL]${NC} $total prompts extracted (expected 150 — still too many!)"
fi

echo ""
echo "  CWE distribution (${#cwe_counts[@]} unique CWEs):"
for cwe in $(echo "${!cwe_counts[@]}" | tr ' ' '\n' | sort); do
    printf "    %-10s : %d\n" "$cwe" "${cwe_counts[$cwe]}"
done

echo ""
echo "  Language distribution:"
for lang in $(echo "${!lang_counts[@]}" | tr ' ' '\n' | sort); do
    printf "    %-10s : %d\n" "$lang" "${lang_counts[$lang]}"
done

echo ""
echo "=========================================="
