# encoding: UTF-8

control "C-5.1.8" do
  title "Ensure at/cron is restricted to authorized users"
  desc  "Configure `/etc/cron.allow` and `/etc/at.allow` to allow specific
users to use these services. If `/etc/cron.allow` or `/etc/at.allow` do not
exist, then `/etc/at.deny` and `/etc/cron.deny` are checked. Any user not
specifically defined in those files is allowed to use at and cron. By removing
the files, only users in `/etc/cron.allow` and `/etc/at.allow` are allowed to
use at and cron. Note that even though a given user is not listed in
`cron.allow` , cron jobs can still be run as that user. The `cron.allow` file
only controls administrative access to the crontab command for scheduling and
modifying cron jobs."
  desc  "rationale", "On many systems, only the system administrator is
authorized to schedule `cron` jobs. Using the `cron.allow` file to control who
can run `cron` jobs enforces this policy. It is easier to manage an allow list
than a deny list. In a deny list, you could potentially add a user ID to the
system and forget to add it to the deny files."
  desc  "check", "
    Run the following commands and ensure `/etc/cron.deny` and `/etc/at.deny`
do not exist:

    ```
    # stat /etc/cron.deny

    stat: cannot stat `/etc/cron.deny': No such file or directory
    ```

    ```
    # stat /etc/at.deny

    stat: cannot stat` /etc/at.deny': No such file or directory
    ```

    Run the following command and verify `Uid` and `Gid` are both `0/root` and
`Access`, does not grant write or execute to group, and does not grant
permissions to `other` for both `/etc/cron.allow` and `/etc/at.allow` :

    ```
    # stat /etc/cron.allow

    Access: (0640/-rw-r-----) Uid: ( 0/ root) Gid: ( 0/ root)
    ```

    ```
    # stat /etc/at.allow

    Access: (0640/-rw-r-----) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  "fix", "
    Run the following commands to remove `/etc/cron.deny` and `/etc/at.deny`
and create and set permissions and ownership for `/etc/cron.allow` and
`/etc/at.allow` :

    ```
    # rm /etc/cron.deny
    # rm /etc/at.deny

    # touch /etc/cron.allow
    # touch /etc/at.allow

    # chmod o-rwx /etc/cron.allow
    # chmod g-wx /etc/cron.allow
    # chmod o-rwx /etc/at.allow
    # chmod g-wx /etc/at.allow

    # chown root:root /etc/cron.allow
    # chown root:root /etc/at.allow
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-3 (3)"]
  tag cis_level: 1
  tag cis_controls: ["14.6"]
  tag cis_cdc_version: "7"
  tag cis_rid: "5.1.8"

  describe file('/etc/cron.deny') do 
    it { should_not exist }
  end
  
  describe file('/etc/at.deny') do 
    it { should_not exist }
  end

  describe file('/etc/cron.allow') do 
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0640') }
  end

  describe file('/etc/at.allow') do 
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
    it { should_not be_more_permissive_than('0640') }
  end
end
