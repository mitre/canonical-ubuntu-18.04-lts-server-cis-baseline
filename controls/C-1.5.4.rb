# encoding: UTF-8

control "C-1.5.4" do
  title "Ensure interactive boot is not enabled"
  desc  "Interactive boot allows console users to interactively select which
services start on boot. Not all distributions support this capability.

    The `PROMPT_FOR_CONFIRM` option provides console users the ability to
interactively boot the system and select which services to start on boot .
  "
  desc  "rationale", "Turn off the `PROMPT_FOR_CONFIRM` option on the console
to prevent console users from potentially overriding established security
settings."
  desc  "check", "
    If interactive boot is available verify it is disabled on your system. On
some distributions this is configured via the `PROMPT_FOR_CONFIRM` option in
`/etc/sysconfig/boot` :

    ```
    # grep \"^PROMPT_FOR_CONFIRM=\" /etc/sysconfig/boot

    PROMPT_FOR_CONFIRM=\"no\"
    ```
  "
  desc "fix", "If interactive boot is available disable it."
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["CM-6", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["5.1", "Rev_7"]
  tag cis_rid: "1.5.4"

  describe file('/etc/sysconfig/boot') do
    its('content') { should match '^\\s*PROMPT_FOR_CONFIRM\\s*=\\s*no' }
  end

end
