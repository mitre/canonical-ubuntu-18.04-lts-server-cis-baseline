# encoding: UTF-8

control "C-5.2.19" do
  title "Ensure SSH warning banner is configured"
  desc  "The `Banner` parameter specifies a file whose contents must be sent to
the remote user before authentication is permitted. By default, no banner is
displayed."
  desc  "rationale", "Banners are used to warn connecting users of the
particular site's policy regarding connection. Presenting a warning message
prior to the normal user login may assist the prosecution of trespassers on the
computer system."
  desc  "check", "
    Run the following command and verify that output matches:

    ```
    # sshd -T | grep banner

    Banner /etc/issue.net
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file to set the parameter as follows:

    ```
    Banner /etc/issue.net
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
  tag cis_rid: "5.2.19"
end
