# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(OPENSSL_DIR ${PROJECT_SOURCE_DIR}/3rdparty/openssl/openssl)

add_subdirectory(host)
if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

# The paths to the arguments used by the tests.
set(OPENSSL_APPS_DIR ${OPENSSL_DIR}/apps)
set(OPENSSL_TEST_DIR ${OPENSSL_DIR}/test)
set(TEST_DATA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test_data)
if (WIN32)
  # Convert the "C:/" to "C/" so that the path can be used by hostfs on Windows.
  string(REPLACE ":" "" OPENSSL_APPS_DIR "${OPENSSL_APPS_DIR}")
  string(REPLACE ":" "" OPENSSL_TEST_DIR "${OPENSSL_TEST_DIR}")
  string(REPLACE ":" "" TEST_DATA_DIR "${TEST_DATA_DIR}")
endif ()

# Add buildtests
file(STRINGS "tests.supported.buildtest" buildtests)
foreach (testcase ${buildtests})
  get_testcase_name(${testcase} name "../../3rdparty/openssl/openssl/test/")
  add_enclave_test(tests/openssl/${name} openssl_host openssl-${name}_enc
                   ${name})
endforeach (testcase)

# Helper for adding tests with arguments.
macro (add_openssl_test TEST_NAME NAME)
  add_enclave_test(tests/openssl/${TEST_NAME} openssl_host openssl-${NAME}_enc
                   ${TEST_NAME} ${ARGN})
endmacro (add_openssl_test)

# Add the rest of the tests.
file(STRINGS "tests.supported" openssltests)
foreach (testcase ${openssltests})
  get_testcase_name(${testcase} name "../../3rdparty/openssl/openssl/test/")

  if ("${name}" STREQUAL asynciotest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL clienthellotest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_TEST_DIR}/session.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL cmsapitest)
    add_openssl_test(
      "${name}" "${name}" ${OPENSSL_TEST_DIR}/certs/servercert.pem
      ${OPENSSL_TEST_DIR}/certs/serverkey.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL ct_test)
    add_openssl_test("${name}" "${name}")
    set_enclave_tests_properties(
      tests/openssl/${name}
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;CT_DIR=${TEST_DATA_DIR}/ct;CERTS_DIR=${TEST_DATA_DIR}/certs"
    )
    continue()
  endif ()

  if ("${name}" STREQUAL d2i_test)
    add_openssl_test("${name}-bad_cert" "${name}" "X509" "decode"
                     ${OPENSSL_TEST_DIR}/d2i-tests/bad_cert.der)
    add_openssl_test("${name}-bad_generalname" "${name}" "GENERAL_NAME"
                     "decode" ${OPENSSL_TEST_DIR}/d2i-tests/bad_generalname.der)
    add_openssl_test("${name}-bad_bio" "${name}" "ASN1_ANY" "BIO"
                     ${OPENSSL_TEST_DIR}/d2i-tests/bad_bio.der)
    add_openssl_test("${name}-high_tag" "${name}" "ASN1_ANY" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/high_tag.der)
    add_openssl_test("${name}-high_tag_integer" "${name}" "ASN1_INTEGER"
                     "decode" ${OPENSSL_TEST_DIR}/d2i-tests/high_tag.der)
    add_openssl_test("${name}-int0" "${name}" "ASN1_INTEGER" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/int0.der)
    add_openssl_test("${name}-int1" "${name}" "ASN1_INTEGER" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/int1.der)
    add_openssl_test("${name}-intminus1" "${name}" "ASN1_INTEGER" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/intminus1.der)
    add_openssl_test("${name}-int0-any" "${name}" "ASN1_ANY" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/int0.der)
    add_openssl_test("${name}-int1-any" "${name}" "ASN1_ANY" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/int1.der)
    add_openssl_test("${name}-intminus1-any" "${name}" "ASN1_ANY" "OK"
                     ${OPENSSL_TEST_DIR}/d2i-tests/intminus1.der)
    add_openssl_test("${name}-bad-int-pad0" "${name}" "ASN1_INTEGER" "decode"
                     ${OPENSSL_TEST_DIR}/d2i-tests/bad-int-pad0.der)
    add_openssl_test(
      "${name}-bad-int-padminus1" "${name}" "ASN1_INTEGER" "decode"
      ${OPENSSL_TEST_DIR}/d2i-tests/bad-int-padminus1.der)
    continue()
  endif ()

  if ("${name}" STREQUAL danetest)
    add_openssl_test(
      "${name}" "${name}" "example.com" ${OPENSSL_TEST_DIR}/danetest.pem
      ${OPENSSL_TEST_DIR}/danetest.in)
    continue()
  endif ()

  if ("${name}" STREQUAL dtlstest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL evp_test)
    add_openssl_test("${name}-evpciph" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evpciph.txt)
    add_openssl_test("${name}-evpdigest" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evpdigest.txt)
    add_openssl_test("${name}-evpencod" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evpencod.txt)
    add_openssl_test("${name}-evpmac" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evpmac.txt)
    add_openssl_test("${name}-evpcase" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evpcase.txt)
    add_openssl_test("${name}-evpccmcavs" "${name}"
                     ${TEST_DATA_DIR}/30-test_evp_data/evpccmcavs.txt)
    continue()
  endif ()

  if ("${name}" STREQUAL fatalerrtest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL ocspapitest)
    add_openssl_test(
      "${name}" "${name}"
      ${OPENSSL_TEST_DIR}/recipes/80-test_ocsp_data/cert.pem
      ${OPENSSL_TEST_DIR}/recipes/80-test_ocsp_data/key.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL recordlentest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL servername_test)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL ssl_test)
    add_openssl_test("${name}-simple" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/01-simple.conf)
    set_enclave_tests_properties(
      tests/openssl/${name}-simple
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    add_openssl_test("${name}-client_auth" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/04-client_auth.conf)
    set_enclave_tests_properties(
      tests/openssl/${name}-client_auth
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    add_openssl_test("${name}-sni" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/05-sni.conf)
    set_enclave_tests_properties(
      tests/openssl/${name}-sni
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    add_openssl_test("${name}-dtls_resumption" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/11-dtls_resumption.conf)
    set_enclave_tests_properties(
      tests/openssl/${name}-dtls_resumption
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    add_openssl_test("${name}-dtls-certstatus" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/16-dtls-certstatus.conf)
    set_enclave_tests_properties(
      tests/openssl/${name}-dtls-certstatus
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    add_openssl_test("${name}-renegotiate" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/17-renegotiate.conf)
    set_enclave_tests_properties(
      tests/openssl/${name}-renegotiate
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    add_openssl_test("${name}-dtls-renegotiate" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/18-dtls-renegotiate.conf)
    set_enclave_tests_properties(
      tests/openssl/${name}-dtls-renegotiate
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    add_openssl_test("${name}-mac-then-encrypt" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/19-mac-then-encrypt.conf)
    set_enclave_tests_properties(
      tests/openssl/${name}-mac-then-encrypt
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    add_openssl_test("${name}-cipher" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/25-cipher.conf)
    set_enclave_tests_properties(
      tests/openssl/${name}-cipher
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    add_openssl_test("${name}-ticket-appdata" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/27-ticket-appdata.conf)
    set_enclave_tests_properties(
      tests/openssl/${name}-ticket-appdata
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    add_openssl_test("${name}-seclevel" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl-tests/28-seclevel.conf)
    set_enclave_tests_properties(
      tests/openssl/${name}-seclevel
      PROPERTIES
      ENVIRONMENT
      "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
    )
    continue()
  endif ()

  if ("${name}" STREQUAL ssl_test_ctx_test)
    add_openssl_test("${name}" "${name}"
                     ${OPENSSL_TEST_DIR}/ssl_test_ctx_test.conf)
    continue()
  endif ()

  if ("${name}" STREQUAL sslapitest)
    set(TMPFILE ${CMAKE_CURRENT_BINARY_DIR}/tmpfile)
    if (WIN32)
      # Convert the "C:/" to "C/" so that the path can be used by hostfs on Windows.
      string(REPLACE ":" "" TMPFILE "${TMPFILE}")
    endif ()
    add_openssl_test(
      "${name}" "${name}" ${OPENSSL_TEST_DIR}/certs
      ${OPENSSL_TEST_DIR}/recipes/90-test_sslapi_data/passwd.txt ${TMPFILE})
    continue()
  endif ()

  if ("${name}" STREQUAL sslbuffertest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL sslcorrupttest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL sysdefaulttest)
    add_openssl_test("${name}" "${name}")
    set_enclave_tests_properties(
      tests/openssl/${name} PROPERTIES ENVIRONMENT
      OPENSSL_CONF=${OPENSSL_TEST_DIR}/sysdefault.cnf)
    continue()
  endif ()

  if ("${name}" STREQUAL tls13ccstest)
    add_openssl_test("${name}" "${name}" ${OPENSSL_APPS_DIR}/server.pem
                     ${OPENSSL_APPS_DIR}/server.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL v3ext)
    add_openssl_test("${name}" "${name}" ${OPENSSL_TEST_DIR}/certs/pathlen.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL verify_extra_test)
    add_openssl_test(
      "${name}" "${name}" ${OPENSSL_TEST_DIR}/certs/roots.pem
      ${OPENSSL_TEST_DIR}/certs/untrusted.pem ${OPENSSL_TEST_DIR}/certs/bad.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL x509_check_cert_pkey_test)
    add_openssl_test(
      "${name}-rsa-cert" "${name}" ${OPENSSL_TEST_DIR}/certs/servercert.pem
      ${OPENSSL_TEST_DIR}/certs/serverkey.pem "cert" "ok")
    add_openssl_test(
      "${name}-mismatched-rsa-cert" "${name}"
      ${OPENSSL_TEST_DIR}/certs/servercert.pem
      ${OPENSSL_TEST_DIR}/certs/wrongkey.pem "cert" "failed")
    add_openssl_test(
      "${name}-dsa-cert" "${name}"
      ${OPENSSL_TEST_DIR}/certs/server-dsa-cert.pem
      ${OPENSSL_TEST_DIR}/certs/server-dsa-key.pem "cert" "ok")
    add_openssl_test(
      "${name}-ec-cert" "${name}"
      ${OPENSSL_TEST_DIR}/certs/server-ecdsa-cert.pem
      ${OPENSSL_TEST_DIR}/certs/server-ecdsa-key.pem "cert" "ok")
    add_openssl_test(
      "${name}-rsa-req" "${name}" ${OPENSSL_TEST_DIR}/certs/x509-check.csr
      ${OPENSSL_TEST_DIR}/certs/x509-check-key.pem "req" "ok")
    add_openssl_test(
      "${name}-mismatched-rsa-req" "${name}"
      ${OPENSSL_TEST_DIR}/certs/x509-check.csr
      ${OPENSSL_TEST_DIR}/certs/wrongkey.pem "req" "failed")
    continue()
  endif ()

  if ("${name}" STREQUAL x509_dup_cert_test)
    add_openssl_test("${name}" "${name}" ${OPENSSL_TEST_DIR}/certs/roots.pem
                     ${OPENSSL_TEST_DIR}/certs/leaf.pem)
    continue()
  endif ()

  if ("${name}" STREQUAL x509aux)
    add_openssl_test(
      "${name}"
      "${name}"
      ${OPENSSL_TEST_DIR}/certs/roots.pem
      ${OPENSSL_TEST_DIR}/certs/root+anyEKU.pem
      ${OPENSSL_TEST_DIR}/certs/root-anyEKU.pem
      ${OPENSSL_TEST_DIR}/certs/root-cert.pem)
    continue()
  endif ()

  # Disable the following tests when using DEBUG_MALLOC.

  # The following tests fail because of the use of setenv.
  if ("${name}" STREQUAL conf_include_test)
    if (NOT USE_DEBUG_MALLOC)
      add_openssl_test(
        "${name}-includes" "${name}"
        ${OPENSSL_TEST_DIR}/recipes/90-test_includes_data/includes.cnf)
      add_openssl_test(
        "${name}-includes-file" "${name}"
        ${OPENSSL_TEST_DIR}/recipes/90-test_includes_data/includes-file.cnf)
      add_openssl_test(
        "${name}-includes-eq" "${name}"
        ${OPENSSL_TEST_DIR}/recipes/90-test_includes_data/includes-eq.cnf)
      add_openssl_test(
        "${name}-includes-eq-ws" "${name}"
        ${OPENSSL_TEST_DIR}/recipes/90-test_includes_data/includes-eq-ws.cnf)
      add_openssl_test(
        "${name}-includes-broken" "${name}"
        ${OPENSSL_TEST_DIR}/recipes/90-test_includes_data/includes-broken.cnf
        "f")
    endif ()
    continue()
  endif ()

  # The following tests fail because of insufficient heap memory.
  if ("${name}" STREQUAL ectest)
    if (NOT USE_DEBUG_MALLOC)
      add_openssl_test("${name}" "${name}")
    endif ()
    continue()
  endif ()
  if ("${name}" STREQUAL evp_test)
    if (NOT USE_DEBUG_MALLOC)
      add_openssl_test("${name}-evppkey" "${name}"
                       ${TEST_DATA_DIR}/30-test_evp_data/evppkey.txt)
      add_openssl_test("${name}-evppkey_ecc" "${name}"
                       ${TEST_DATA_DIR}/30-test_evp_data/evppkey_ecc.txt)
    endif ()
    continue()
  endif ()
  if ("${name}" STREQUAL ssl_test)
    if (NOT USE_DEBUG_MALLOC)
      add_openssl_test("${name}-protocol-version" "${name}"
                       ${OPENSSL_TEST_DIR}/ssl-tests/02-protocol-version.conf)
      set_enclave_tests_properties(
        tests/openssl/${name}-protocol-version
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
      add_openssl_test(
        "${name}-dtls-protocol-version" "${name}"
        ${OPENSSL_TEST_DIR}/ssl-tests/07-dtls-protocol-version.conf)
      set_enclave_tests_properties(
        tests/openssl/${name}-dtls-protocol-version
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
      add_openssl_test("${name}-resumption" "${name}"
                       ${OPENSSL_TEST_DIR}/ssl-tests/10-resumption.conf)
      set_enclave_tests_properties(
        tests/openssl/${name}-resumption
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
      add_openssl_test("${name}-cert-select" "${name}"
                       ${OPENSSL_TEST_DIR}/ssl-tests/20-cert-select.conf)
      set_enclave_tests_properties(
        tests/openssl/${name}-cert-select
        PROPERTIES
        ENVIRONMENT
        "CTLOG_FILE=${OPENSSL_TEST_DIR}/ct/log_list.conf;TEST_CERTS_DIR=${OPENSSL_TEST_DIR}/certs"
      )
    endif ()
    continue()
  endif ()

  add_openssl_test("${name}" "${name}")
endforeach (testcase)
