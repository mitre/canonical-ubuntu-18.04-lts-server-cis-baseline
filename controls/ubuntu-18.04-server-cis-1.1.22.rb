# encoding: UTF-8

control "C-1.1.22" do
  title "Disable Automounting"
  desc  "`autofs` allows automatic mounting of devices, typically including
CD/DVDs and USB drives."
  desc  "rationale", "With automounting enabled anyone with physical access
could attach a USB drive or disc and have its contents available in system even
if they lacked permissions to mount it themselves."
  desc  "check", "
    autofs should be removed or disabled.

    Run the following commands to verify that `autofs` is not installed or is
disabled

    Run the following command to verify `autofs` is not enabled:

    ```
    # systemctl is-enabled autofs

    disabled
    ```

    Verify result is not \"enabled\".

    OR

    Run the following command to verfiy that `autofs` is not installed

    ```
    # dpkg -s autofs
    ```

    Output should include:

    ```
    package `autofs` is not installed
    ```
  "
  desc  "fix", "
    Run one of the following commands:

    Run the following command to disable `autofs` :

    ```
    # systemctl --now disable autofs
    ```

    OR

    Run the following command to remove `autofs`

    ```
    # apt purge autofs
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
  tag nist: ["SI-3", "SC-18(4)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["8.4", "8.5", "Rev_7"]
  tag cis_rid: "1.1.22"

  describe service('autofs') do
    it { should_not be_enabled }
  end

end
