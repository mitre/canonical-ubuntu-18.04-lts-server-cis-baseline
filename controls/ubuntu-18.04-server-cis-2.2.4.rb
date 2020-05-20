# encoding: UTF-8

control "C-2.2.4" do
  title "Ensure CUPS is not enabled"
  desc  "The Common Unix Print System (CUPS) provides the ability to print to
both local and network printers. A system running CUPS can also accept print
jobs from remote systems and print them to local printers. It also provides a
web based remote administration capability."
  desc  "rationale", "If the system does not need to print jobs or accept print
jobs from other systems, it is recommended that CUPS be disabled to reduce the
potential attack surface."
  desc  "check", "
    Run the following command to verify `cups` is not enabled:

    ```
    # systemctl is-enabled cups

    disabled
    ```

    Verify result is not \"enabled\".
  "
  desc  "fix", "
    Run one of the following commands to disable `cups` :

    ```
    # systemctl --now disable cups
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
  tag cis_rid: "2.2.4"

  if package('cups').installed?
    describe service('cups') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  else
    impact 0.0
    describe "The Common Unix Print System (CUPS) package is not installed" do
      skip "The Common Unix Print System (CUPS) package is not installed, this control is Not Applicable."
    end
  end

end
