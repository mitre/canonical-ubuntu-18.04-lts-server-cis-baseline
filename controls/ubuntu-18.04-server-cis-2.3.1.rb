# encoding: UTF-8

control "C-2.3.1" do
  title "Ensure NIS Client is not installed"
  desc  "The Network Information Service (NIS), formerly known as Yellow Pages,
is a client-server directory service protocol used to distribute system
configuration files. The NIS client was used to bind a machine to an NIS server
and receive the distributed configuration files."
  desc  "rationale", "The NIS service is inherently an insecure system that has
been vulnerable to DOS attacks, buffer overflows and has poor authentication
for querying NIS maps. NIS generally has been replaced by such protocols as
Lightweight Directory Access Protocol (LDAP). It is recommended that the
service be removed."
  desc  "check", "
    Verify `nis` is not installed. Use the following command to provide the
needed information:

    ```
    dpkg -s nis
    ```
  "
  desc "fix", "
    Uninstall `nis`:

    ```
    apt purge nis
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
  tag nist: ["CM-2 (2)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["2.6", "Rev_7"]
  tag cis_rid: "2.3.1"

  describe package('nis') do
    it { should_not be_installed }
  end
end
