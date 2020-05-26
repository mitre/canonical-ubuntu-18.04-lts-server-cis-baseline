# encoding: UTF-8

control "C-3.4.2" do
  title "Ensure SCTP is disabled"
  desc  "The Stream Control Transmission Protocol (SCTP) is a transport layer
protocol used to support message oriented communication, with several streams
of messages in one connection. It serves a similar function as TCP and UDP,
incorporating features of both. It is message-oriented like UDP, and ensures
reliable in-sequence transport of messages with congestion control like TCP."
  desc  "rationale", "If the protocol is not being used, it is recommended that
kernel module not be loaded, disabling the service to reduce the potential
attack surface."
  desc  "check", "
    Run the following commands and verify the output is as indicated:

    ```
    # modprobe -n -v sctp

    install /bin/true
    ```

    ```
    # lsmod | grep sctp

    ```
  "
  desc "fix", "
    Edit or create a file in the `/etc/modprobe.d/` directory ending in .conf

    Example: `vi /etc/modprobe.d/sctp.conf`

    and add the following line:

    ```
    install sctp /bin/true
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
  tag cis_rid: "3.4.2"

  describe kernel_module('sctp') do
    it { should_not be_loaded }
    it { should_not be_disabled }
    it { should_not be_blacklisted }
  end
end
