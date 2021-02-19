# encoding: UTF-8

control "C-5.2.6" do
  title "Ensure SSH X11 forwarding is disabled"
  desc  "The X11Forwarding parameter provides the ability to tunnel X11 traffic
through the connection to enable remote graphic connections."
  desc  "rationale", "Disable X11 forwarding unless there is an operational
requirement to use X11 applications directly. There is a small risk that the
remote X11 servers of users who are logged in via SSH with X11 forwarding could
be compromised by other users on the X11 server. Note that even if X11
forwarding is disabled, users can always install their own forwarders."
  desc  "check", "
    Run the following command and verify that output matches:

    ```
    # sshd -T | grep x11forwarding

    X11Forwarding no
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file to set the parameter as follows:

    ```
    X11Forwarding no
    ```
  "
  impact 0.7
  tag severity: "high"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["CM-7 (1)", "Rev_4"]
  tag cis_level: 2
  tag cis_controls: ["9.2", "Rev_7"]
  tag cis_rid: "5.2.6"
  describe parse_config_file('/etc/ssh/sshd_config', { assignment_regex: /^\s*(\S*)\s*(.*?)\s*$/ } ) do
    its('X11Forwarding') { should cmp 'no' }
  end
end
