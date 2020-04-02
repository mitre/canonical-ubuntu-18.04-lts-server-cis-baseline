# encoding: UTF-8

control "C-6.1.8" do
  title "Ensure permissions on /etc/group- are configured"
  desc  "The `/etc/group-` file contains a backup list of all the valid groups
defined in the system."
  desc  "rationale", "It is critical to ensure that the `/etc/group-` file is
protected from unauthorized access. Although it is protected by default, the
file permissions could be changed either inadvertently or through malicious
actions."
  desc  "check", "
    Run the following command and verify `Uid` and `Gid` are both `0/root` and
`Access` is `644` or more restrictive:

    ```
    # stat /etc/group-

    Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  "fix", "
    Run the following command to set permissions on `/etc/group-` :

    ```
    # chown root:root /etc/group-

    # chmod u-x,go-wx /etc/group-
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
  tag nist: ["SC-28", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["16.4", "Rev_7"]
  tag cis_rid: "6.1.8"
end
