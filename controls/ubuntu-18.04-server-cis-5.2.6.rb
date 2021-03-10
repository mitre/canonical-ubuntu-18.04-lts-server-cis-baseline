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
  tag nist: ["CM-7 (1)"]
  tag cis_level: 2
  tag cis_controls: ["9.2"]
  tag cis_rid: "5.2.6"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  describe sshd_config do
    its('X11Forwarding') { should cmp 'no' }
  end
end
