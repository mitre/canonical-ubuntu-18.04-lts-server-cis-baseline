# encoding: UTF-8

control "C-6.2.6" do
  title "Ensure root is the only UID 0 account"
  desc  "Any account with UID 0 has superuser privileges on the system."
  desc  "rationale", "This access must be limited to only the default `root`
account and only from the system console. Administrative access must be through
an unprivileged account using an approved mechanism as noted in Item 5.6 Ensure
access to the su command is restricted."
  desc  "check", "
    Run the following command and verify that only \"root\" is returned:

    ```
    # awk -F: '($3 == 0) { print $1 }' /etc/passwd

    root
    ```
  "
  desc "fix", "Remove any users other than `root` with UID `0` or assign them
a new UID if appropriate."
  impact 0.5
  tag severity: "medium"
  tag nist: ["SC-2"]
  tag cis_level: 1
  tag cis_controls: ["4.6"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.2.6"

  describe passwd.uids(0) do
    its('users') { should cmp 'root' }
    its('count') { should eq 1 }
  end
end
