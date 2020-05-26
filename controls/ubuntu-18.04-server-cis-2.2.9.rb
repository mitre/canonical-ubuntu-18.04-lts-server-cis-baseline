# encoding: UTF-8

control "C-2.2.9" do
  title "Ensure FTP Server is not enabled"
  desc  "The File Transfer Protocol (FTP) provides networked computers with the
ability to transfer files."
  desc  "rationale", "FTP does not protect the confidentiality of data or
authentication credentials. It is recommended SFTP be used if file transfer is
required. Unless there is a need to run the system as a FTP server (for
example, to allow anonymous downloads), it is recommended that the package be
deleted to reduce the potential attack surface."
  desc  "check", "
    Run the following command to verify `vsftpd` is not enabled:

    ```
    # systemctl is-enabled vsftpd

    disabled
    ```

    Verify result is not \"enabled\".
  "
  desc  "fix", "
    Run the following command to disable `vsftpd`:

    ```
    # systemctl --now disable vsftpd
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
  tag cis_rid: "2.2.9"

  if package('vsftpd').installed? || package('ftpd').installed? || package('gesftpserver').installed? || package('pure-ftpd').installed? || package('proftpd-basic').installed?
    describe service('vsftpd') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
    describe service('pure-ftpd') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
    describe service('proftpd') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
    describe package('ftpd') do
      it { should_not be_installed}
    end
    describe package('gesftpserver') do
      it { should_not be_installed}
    end
  else
    impact 0.0
    describe "An FTP Server package is not installed" do
      skip "An FTP Server package is not installed."
    end
  end
end


