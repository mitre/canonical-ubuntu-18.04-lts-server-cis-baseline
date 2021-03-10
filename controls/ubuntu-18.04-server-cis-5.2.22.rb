# encoding: UTF-8

control "C-5.2.22" do
  title "Ensure SSH MaxStartups is configured"
  desc  "The `MaxStartups` parameter specifies the maximum number of concurrent
unauthenticated connections to the SSH daemon."
  desc  "rationale", "To protect a system from denial of service due to a large
number of pending authentication connection attempts, use the rate limiting
function of MaxStartups to protect availability of sshd logins and prevent
overwhelming the daemon."
  desc  "check", "
    Run the following command and verify that output `MaxStartups` is
`10:30:60` or matches site policy:

    ```
    # sshd -T | grep -i maxstartups

    # MaxStartups 10:30:60
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file to set the parameter as follows:

    ```
    maxstartups 10:30:60
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["CM-6"]
  tag cis_level: 1
  tag cis_controls: ["5.1"]
  tag cis_rid: "5.2.22"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  describe sshd_config do
    its('MaxStartups') { should cmp '10:30:60' }
  end
end
