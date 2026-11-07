# Source this file in your current shell: . ./unload-ibm-token.sh
# Removes QISKIT_IBM_TOKEN from the environment. ~/.ibm is left untouched.
_qipher_unload_ibm_token() {
    if [ -z "${QISKIT_IBM_TOKEN+x}" ]; then
        printf 'QISKIT_IBM_TOKEN is not set\n' >&2
        return 0
    fi

    unset QISKIT_IBM_TOKEN
    printf '%s\n' 'QISKIT_IBM_TOKEN unset; circuits will use BasicSimulator'
}
_qipher_unload_ibm_token
_qipher_unload_status=$?
unset -f _qipher_unload_ibm_token
return "$_qipher_unload_status" 2>/dev/null || exit "$_qipher_unload_status"
