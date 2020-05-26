# encoding: UTF-8

control "C-2.2.17" do
  title "Ensure NIS Server is not enabled"
  desc  "The Network Information Service (NIS) (formally known as Yellow Pages)
is a client-server directory service protocol for distributing system
configuration files. The NIS server is a collection of programs that allow for
the distribution of configuration files."
  desc  "rationale", "The NIS service is inherently an insecure system that has
been vulnerable to DOS attacks, buffer overflows and has poor authentication
for querying NIS maps. NIS generally has been replaced by such protocols as
Lightweight Directory Access Protocol (LDAP). It is recommended that the
service be disabled and other, more secure services be used"
  desc  "check", "
    Run the following command to verify `nis` is not enabled:

    ```
    # systemctl is-enabled nis

    disabled
    ```

    Verify result is not \"enabled\".
  "
  desc  "fix", "
    Run the following command to disable `nis`:

    ```
    # systemctl --now disable nis
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
  tag cis_rid: "2.2.17"

  describe service('nis') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
end
