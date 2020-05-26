# encoding: UTF-8

control "C-2.2.16" do
  title "Ensure rsync service is not enabled"
  desc  "The `rsyncd` service can be used to synchronize files between systems
over network links."
  desc  "rationale", "The `rsyncd` service presents a security risk as it uses
unencrypted protocols for communication."
  desc  "check", "
    Run the following command to verify `rsyncd` is not enabled:

    ```
    # systemctl is-enabled rsync

    disabled
    ```

    Verify result is not \"enabled\".
  "
  desc  "fix", "
    Run the following command to disable `rsyncd`:

    ```
    # systemctl --now disable rsync
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
  tag nist: ["CM-7 (1)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["9.2", "Rev_7"]
  tag cis_rid: "2.2.16"

    describe service('rsync') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
end
