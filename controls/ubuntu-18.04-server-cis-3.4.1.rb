# encoding: UTF-8

control "C-3.4.1" do
  title "Ensure DCCP is disabled"
  desc  "The Datagram Congestion Control Protocol (DCCP) is a transport layer
protocol that supports streaming media and telephony. DCCP provides a way to
gain access to congestion control, without having to do it at the application
layer, but does not provide in-sequence delivery."
  desc  "rationale", "If the protocol is not required, it is recommended that
the drivers not be installed to reduce the potential attack surface."
  desc  "check", "
    Run the following commands and verify the output is as indicated:

    ```
    # modprobe -n -v dccp

    install /bin/true
    ```

    ```
    # lsmod | grep dccp

    ```
  "
  desc "fix", "
    Edit or create a file in the `/etc/modprobe.d/` directory ending in .conf

    Example: `vi /etc/modprobe.d/dccp.conf`

    and add the following line:

    ```
    install dccp /bin/true
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
  tag cis_rid: "3.4.1"


  describe kernel_module('dccp') do
    it { should_not be_loaded }
    it { should_not be_disabled }
    it { should_not be_blacklisted }
  end
end