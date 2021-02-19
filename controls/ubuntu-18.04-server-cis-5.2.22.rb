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
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["CM-6", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["5.1", "Rev_7"]
  tag cis_rid: "5.2.22"
  describe parse_config_file('/etc/ssh/sshd_config', { assignment_regex: /^\s*(\S*)\s*(.*?)\s*$/ } ) do
    its('MaxStartups') { should cmp '10:30:60' }
  end
end
