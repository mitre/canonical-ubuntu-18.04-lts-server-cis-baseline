# encoding: UTF-8

control "C-5.1.6" do
  title "Ensure permissions on /etc/cron.monthly are configured"
  desc  "The `/etc/cron.monthly` directory contains system cron jobs that need
to run on a monthly basis. The files in this directory cannot be manipulated by
the `crontab` command, but are instead edited by system administrators using a
text editor. The commands below restrict read/write and search access to user
and group root, preventing regular users from accessing this directory."
  desc  "rationale", "Granting write access to this directory for
non-privileged users could provide them the means for gaining unauthorized
elevated privileges. Granting read access to this directory could give an
unprivileged user insight in how to gain elevated privileges or circumvent
auditing controls."
  desc  "check", "
    Run the following command and verify `Uid` and `Gid` are both `0/root` and
`Access` does not grant permissions to `group` or `other` :

    ```
    # stat /etc/cron.monthly

    Access: (0700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  "fix", "
    Run the following commands to set ownership and permissions on
`/etc/cron.monthly` :

    ```
    # chown root:root /etc/cron.monthly
    ```

    ```
    # chmod og-rwx /etc/cron.monthly
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-3 (3)"]
  tag cis_level: 1
  tag cis_controls: ["14.6"]
  tag cis_cdc_version: "7"
  tag cis_rid: "5.1.6"

  describe file('/etc/cron.monthly') do 
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should be_directory }
    it { should_not be_more_permissive_than('0700') }
  end
end
