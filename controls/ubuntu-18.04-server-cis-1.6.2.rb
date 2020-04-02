# encoding: UTF-8

control "C-1.6.2" do
  title "Ensure address space layout randomization (ASLR) is enabled"
  desc  "Address space layout randomization (ASLR) is an exploit mitigation
technique which randomly arranges the address space of key data areas of a
process."
  desc  "rationale", "Randomly placing virtual memory regions will make it
difficult to write memory page exploits as the memory placement will be
consistently shifting."
  desc  "check", "
    Run the following commands and verify output matches:

    ```
    # sysctl kernel.randomize_va_space

    kernel.randomize_va_space = 2
    ```

    ```
    # grep \"kernel\\.randomize_va_space\" /etc/sysctl.conf /etc/sysctl.d/*

    kernel.randomize_va_space = 2
    ```
  "
  desc  "fix", "
    Set the following parameter in `/etc/sysctl.conf` or a `/etc/sysctl.d/*`
file:

    ```
    kernel.randomize_va_space = 2
    ```

    Run the following command to set the active kernel parameter:

    ```
    # sysctl -w kernel.randomize_va_space=2
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
  tag nist: ["SI-16", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["8.3", "Rev_7"]
  tag cis_rid: "1.6.2"

  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should cmp 2 }
  end

end
