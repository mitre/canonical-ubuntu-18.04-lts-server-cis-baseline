# encoding: UTF-8

control "C-3.4.4" do
  title "Ensure TIPC is disabled"
  desc  "The Transparent Inter-Process Communication (TIPC) protocol is
designed to provide communication between cluster nodes."
  desc  "rationale", "If the protocol is not being used, it is recommended that
kernel module not be loaded, disabling the service to reduce the potential
attack surface."
  desc  "check", "
    Run the following commands and verify the output is as indicated:

    ```
    # modprobe -n -v tipc

    install /bin/true
    ```

    ```
    # lsmod | grep tipc

    ```
  "
  desc "fix", "
    Edit or create a file in the `/etc/modprobe.d/` directory ending in .conf

    Example: `vi /etc/modprobe.d/tipc.conf`

    and add the following line:

    ```
    install tipc /bin/true
    ```
  "
  impact 0.7
  tag severity: "high"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["CM-7 (1)", "Rev_4"]
  tag cis_level: 2
  tag cis_controls: ["9.2", "Rev_7"]
  tag cis_rid: "3.4.4"

  describe kernel_module('tipc') do
    it { should_not be_loaded }
    it { should_not be_disabled }
    it { should_not be_blacklisted }
  end
end
