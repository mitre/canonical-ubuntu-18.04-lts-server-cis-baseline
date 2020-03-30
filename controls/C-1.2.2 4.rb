# encoding: UTF-8

control "C-1.2.2" do
  title "Ensure GPG keys are configured"
  desc  "Most packages managers implement GPG key signing to verify package
integrity during installation."
  desc  "rationale", "It is important to ensure that updates are obtained from
a valid source to protect against spoofing that could lead to the inadvertent
installation of malware on the system."
  desc  "check", "
    Verify GPG keys are configured correctly for your package manager:

    ```
    # apt-key list
    ```
  "
  desc "fix", "Update your package manager GPG keys in accordance with site
policy."
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["SI-2", "SI-2", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["3.4", "3.5", "Rev_7"]
  tag cis_rid: "1.2.2"
end
