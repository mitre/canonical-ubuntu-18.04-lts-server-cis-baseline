# encoding: UTF-8

control "C-1.4.2" do
  title "Ensure filesystem integrity is regularly checked"
  desc  "Periodic checking of the filesystem integrity is needed to detect
changes to the filesystem."
  desc  "rationale", "Periodic file checking allows the system administrator to
determine on a regular basis if critical files have been changed in an
unauthorized fashion."
  desc  "check", "
    Run the following to verify that aidcheck.service and aidcheck.timer are
enabled and running

    ```
    # systemctl is-enabled aidecheck.service
    # systemctl status aidecheck.service

    # systemctl is-enabled aidecheck.timer
    # systemctl status aidecheck.timer
    ```
    OR

    Run the following commands to determine if there is a `cron` job scheduled
to run the aide check.

    ```
    # crontab -u root -l | grep aide

    # grep -r aide /etc/cron.* /etc/crontab
    ```

    Ensure a cron job in compliance with site policy is returned.
  "
  desc  "fix", "
    Run the following commands:

    ```
    # cp ./config/aidecheck.service /etc/systemd/system/aidecheck.service
    # cp ./config/aidecheck.timer /etc/systemd/system/aidecheck.timer
    # chmod 0644 /etc/systemd/system/aidecheck.*

    # systemctl reenable aidecheck.timer
    # systemctl restart aidecheck.timer
    # systemctl daemon-reload
    ```

    OR

    Run the following command:

    ```
    # crontab -u root -e
    ```

    Add the following line to the crontab:

    ```
    0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check
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
  tag nist: ["AU-2", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["14.9", "Rev_7"]
  tag cis_rid: "1.4.2"

  describe.one do
    describe service('aide') do
      it { should be_installed }
      it { should be_enabled }
      it { should be_running }
    end

    describe crontab('root') do
      its('user') { should include 'root'}
      its('commands') { should include '/usr/bin/aide --check' }
    end
  end





end
