# encoding: UTF-8

control "C-5.1.2" do
  title "Ensure permissions on /etc/crontab are configured"
  desc  "The `/etc/crontab` file is used by `cron` to control its own jobs. The
commands in this item make sure that root is the user and group owner of the
file and that only the owner can access the file."
  desc  "rationale", "This file contains information on what system jobs are
run by cron. Write access to these files could provide unprivileged users with
the ability to elevate their privileges. Read access to these files could
provide users with the ability to gain insight on system jobs that run on the
system and could provide them a way to gain unauthorized privileged access."
  desc  "check", "
    Run the following command and verify `Uid` and `Gid` are both `0/root` and
`Access` does not grant permissions to `group` or `other` :

    ```
    # stat /etc/crontab

    Access: (0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  "fix", "
    Run the following commands to set ownership and permissions on
`/etc/crontab` :

    ```
    # chown root:root /etc/crontab
    ```

    ```
    # chmod og-rwx /etc/crontab
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-3 (3)"]
  tag cis_level: 1
  tag cis_controls: ["14.6"]
  tag cis_cdc_version: "7"
  tag cis_rid: "5.1.2"

  describe file('/etc/crontab') do 
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0600') }
  end
end
