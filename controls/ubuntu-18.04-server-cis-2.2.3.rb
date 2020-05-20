# encoding: UTF-8

control "C-2.2.3" do
  title "Ensure Avahi Server is not enabled"
  desc  "Avahi is a free zeroconf implementation, including a system for
multicast DNS/DNS-SD service discovery. Avahi allows programs to publish and
discover services and hosts running on a local network with no specific
configuration. For example, a user can plug a computer into a network and Avahi
automatically finds printers to print to, files to look at and people to talk
to, as well as network services running on the machine."
  desc  "rationale", "Automatic discovery of network services is not normally
required for system functionality. It is recommended to disable the service to
reduce the potential attack surface."
  desc  "check", "
    Run the following command to verify `avahi-daemon` is not enabled:

    ```
    # systemctl is-enabled avahi-daemon

    disabled
    ```

    Verify result is not \"enabled\".
  "
  desc  "fix", "
    Run the following command to disable `avahi-daemon`:

    ```
    # systemctl --now disable avahi-daemon
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
  tag cis_rid: "2.2.3"

  if package('avahi-daemon').installed?
    describe service('avahi-daemon') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  else
    impact 0.0
    describe "The Avahi Server package is not installed" do
      skip "The Avahi Server package is not installed, this control is Not Applicable."
    end
  end

end
