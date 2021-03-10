# encoding: UTF-8

control "C-5.2.5" do
  title "Ensure SSH LogLevel is appropriate"
  desc  "`INFO` level is the basic level that only records login activity of
SSH users. In many situations, such as Incident Response, it is important to
determine when a particular user was active on a system. The logout record can
eliminate those users who disconnected, which helps narrow the field.

    `VERBOSE` level specifies that login and logout activity as well as the key
fingerprint for any SSH key used for login will be logged. This information is
important for SSH key management, especially in legacy environments.
  "
  desc  "rationale", "SSH provides several logging levels with varying amounts
of verbosity. `DEBUG` is specifically **not** recommended other than strictly
for debugging SSH communications since it provides so much data that it is
difficult to identify important security information."
  desc  "check", "
    Run the following command and verify that output matches:

    ```
    # sshd -T | grep loglevel
    ```

    ```
    LogLevel VERBOSE
    ```

    OR

    ```
    loglevel INFO
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file to set the parameter as follows:

    ```
    LogLevel VERBOSE
    ```

    OR

    ```
    LogLevel INFO
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["AU-12", "AU-3"]
  tag cis_level: 1
  tag cis_controls: ["6.2", "6.3"]
  tag cis_rid: "5.2.5"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  describe sshd_config do
    its('LogLevel') { should match(/^VERBOSE|INFO$/) }
  end
end
