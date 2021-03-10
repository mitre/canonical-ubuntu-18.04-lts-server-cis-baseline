# encoding: UTF-8

control "C-5.2.4" do
  title "Ensure SSH Protocol is not set to 1"
  desc  "Older versions of SSH support two different and incompatible
protocols: SSH1 and SSH2. SSH1 was the original protocol and was subject to
security issues. SSH2 is more advanced and secure."
  desc  "rationale", "SSH v1 suffers from insecurities that do not affect SSH
v2."
  desc  "check", "
    Run the following command:

    ```
    # sshd -T | grep -Ei '^\\s*protocol\\s+(1|1\\s*,\\s*2|2\\s*,\\s*1)\\s*'
    ```

    Nothing should be returned
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file to set the parameter as follows:

    ```
    Protocol 2
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["SC-8", "IA-2 (1)"]
  tag cis_level: 1
  tag cis_controls: ["14.4", "4.5"]
  tag cis_rid: "5.2.4"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  describe sshd_config do
    its('Protocol') { should cmp 2 }
  end
end
