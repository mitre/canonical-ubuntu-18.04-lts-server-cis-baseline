# encoding: UTF-8

control "C-2.2.15" do
  title "Ensure mail transfer agent is configured for local-only mode"
  desc  "Mail Transfer Agents (MTA), such as sendmail and Postfix, are used to
listen for incoming mail and transfer the messages to the appropriate user or
mail server. If the system is not intended to be a mail server, it is
recommended that the MTA be configured to only process local mail."
  desc  "rationale", "The software for all Mail Transfer Agents is complex and
most have a long history of security issues. While it is important to ensure
that the system can process local mail messages, it is not necessary to have
the MTA's daemon listening on a port unless the server is intended to be a mail
server that receives and processes mail from other systems."
  desc  "check", "
    Run the following command to verify that the MTA is not listening on any
non-loopback address ( `127.0.0.1` or `::1` )

    Nothing should be returned

    ```
    # ss -lntu | grep -E ':25\\s' | grep -E -v '\\s(127.0.0.1|::1):25\\s'
    ```
  "
  desc "fix", "
    Edit `/etc/postfix/main.cf` and add the following line to the RECEIVING
MAIL section. If the line already exists, change it to look like the line below:

    ```
    inet_interfaces = loopback-only
    ```

    Restart postfix:

    ```
    # systemctl restart postfix
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
  tag cis_rid: "2.2.15"

  describe.one do
    describe port(25) do
      it { should be_listening }
      its('protocols') { should include 'tcp' }
      its('addresses') { should include '127.0.0.1' }
    end
    describe port(25) do
      it { should_not be_listening }
    end
  end
end

