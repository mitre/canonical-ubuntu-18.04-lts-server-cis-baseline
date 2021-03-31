# encoding: UTF-8

control "C-5.1.7" do
  title "Ensure permissions on /etc/cron.d are configured"
  desc  "The `/etc/cron.d` directory contains system `cron` jobs that need to
run in a similar manner to the hourly, daily weekly and monthly jobs from
`/etc/crontab` , but require more granular control as to when they run. The
files in this directory cannot be manipulated by the `crontab` command, but are
instead edited by system administrators using a text editor. The commands below
restrict read/write and search access to user and group root, preventing
regular users from accessing this directory."
  desc  "rationale", "Granting write access to this directory for
non-privileged users could provide them the means for gaining unauthorized
elevated privileges. Granting read access to this directory could give an
unprivileged user insight in how to gain elevated privileges or circumvent
auditing controls."
  desc  "check", "
    Run the following command and verify `Uid` and `Gid` are both `0/root` and
`Access` does not grant permissions to `group` or `other` :

    ```
    # stat /etc/cron.d

    Access: (0700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  "fix", "
    Run the following commands to set ownership and permissions on
`/etc/cron.d` :

    ```
    # chown root:root /etc/cron.d
    ```

    ```
    # chmod og-rwx /etc/cron.d
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-3 (3)"]
  tag cis_level: 1
  tag cis_controls: ["14.6"]
  tag cis_cdc_version: "7"
  tag cis_rid: "5.1.7"

  describe file('/etc/cron.d') do 
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should be_directory }
    it { should_not be_more_permissive_than('0700') }
  end
end
