{
  buildPythonPackage,
  setuptools,
  cbor2,
  dbus-next,
}:
buildPythonPackage {
  pname = "tpm-passkey-test";
  version = "0.1.0";
  pyproject = true;
  src = ./python;
  build-system = [ setuptools ];
  dependencies = [
    cbor2
    dbus-next
  ];
  pythonImportsCheck = [
    "tpm_passkey_test"
    "tpm_test_bus"
  ];
}
