# Source this file in your current shell: . ./load-ibm-token.sh
# ~/.ibm must contain only the raw IBM Quantum Platform API token.
_qipher_load_ibm_token() {
    if [ ! -r "$HOME/.ibm" ]; then
        printf 'Cannot read %s/.ibm\n' "$HOME" >&2
        return 1
    fi

    _qipher_token=$(cat "$HOME/.ibm") || return 1
    if [ -z "$_qipher_token" ]; then
        printf '%s\n' 'IBM token file is empty' >&2
        unset _qipher_token
        return 1
    fi

    export QISKIT_IBM_TOKEN="$_qipher_token"
    unset _qipher_token
}
_qipher_load_ibm_token
_qipher_load_status=$?
unset -f _qipher_load_ibm_token
return "$_qipher_load_status" 2>/dev/null || exit "$_qipher_load_status"
