# encoding: UTF-8

control "C-4.1.1.1" do
  title "Ensure auditd is installed"
  desc  "auditd is the userspace component to the Linux Auditing System. It's
responsible for writing audit records to the disk"
  desc  "rationale", "The capturing of system events provides system
administrators with information to allow them to determine if unauthorized
access to their system is occurring."
  desc  "check", "
    Run the following command and verify auditd is installed:

    ```
    # dpkg -s auditd audispd-plugins
    ```
  "
  desc  "fix", "
    Run the following command to Install auditd

    ```
    # apt install auditd audispd-plugins
    ```
  "
  impact 0.7
  tag severity: "high"
  tag nist: ["AU-12", "AU-3"]
  tag cis_level: 2
  tag cis_controls: ["6.2", "6.3"]
  tag cis_cdc_version: "7"
  tag cis_rid: "4.1.1.1"

  describe package('auditd') do
    it { should be_installed }
  end
  
  describe package('audispd-plugins') do
    it { should be_installed }
  end
end
