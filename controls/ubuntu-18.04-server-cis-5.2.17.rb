# encoding: UTF-8

control "C-5.2.17" do
  title "Ensure SSH LoginGraceTime is set to one minute or less"
  desc  "The `LoginGraceTime` parameter specifies the time allowed for
successful authentication to the SSH server. The longer the Grace period is the
more open unauthenticated connections can exist. Like other session controls in
this session the Grace Period should be limited to appropriate organizational
limits to ensure the service is available for needed access."
  desc  "rationale", "Setting the `LoginGraceTime` parameter to a low number
will minimize the risk of successful brute force attacks to the SSH server. It
will also limit the number of concurrent unauthenticated connections While the
recommended setting is 60 seconds (1 Minute), set the number based on site
policy."
  desc  "check", "
    Run the following command and verify that output `LoginGraceTime` is
between 1 and 60:

    ```
    # sshd -T | grep logingracetime

    LoginGraceTime 60
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file to set the parameter as follows:

    ```
    LoginGraceTime 60
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
  tag cis_rid: "5.2.17"
  describe parse_config_file('/etc/ssh/sshd_config', { assignment_regex: /^\s*(\S*)\s*(\d*?)\s*$/ } ) do
    its('LoginGraceTime') { should cmp >= 1 }
    its('LoginGraceTime') { should cmp <= 60 }
  end
end
