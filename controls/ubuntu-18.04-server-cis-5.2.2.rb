# encoding: UTF-8

control "C-5.2.2" do
  title "Ensure permissions on SSH private host key files are configured"
  desc  "An SSH private key is one of two files used in SSH public key
authentication. In this authentication method, The possession of the private
key is proof of identity. Only a private key that corresponds to a public key
will be able to authenticate successfully. The private keys need to be stored
and handled carefully, and no copies of the private key should be distributed."
  desc  "rationale", "If an unauthorized user obtains the private SSH host key
file, the host could be impersonated"
  desc  "check", "
    Run the following command and verify Uid is 0/root and and Gid is 0/root.
Ensure group and other do not have permissions

    ```
    # find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \\;

     File: ‘/etc/ssh/ssh_host_rsa_key’
     Size: 1679 Blocks: 8 IO Block: 4096 regular file
    Device: ca01h/51713d Inode: 8628138 Links: 1
    Access: (0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/root)
    Access: 2018-10-22 18:24:56.861750616 +0000
    Modify: 2018-10-22 18:24:56.861750616 +0000
    Change: 2018-10-22 18:24:56.873750616 +0000
     Birth: -
     File: ‘/etc/ssh/ssh_host_ecdsa_key’
     Size: 227 Blocks: 8 IO Block: 4096 regular file
    Device: ca01h/51713d Inode: 8631760 Links: 1
    Access: (0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/root)
    Access: 2018-10-22 18:24:56.897750616 +0000
    Modify: 2018-10-22 18:24:56.897750616 +0000
    Change: 2018-10-22 18:24:56.905750616 +0000
     Birth: -
     File: ‘/etc/ssh/ssh_host_ed25519_key’
     Size: 387 Blocks: 8 IO Block: 4096 regular file
    Device: ca01h/51713d Inode: 8631762 Links: 1
    Access: (0600/-rw-------) Uid: ( 0/ root) Gid: ( 0/root)
    Access: 2018-10-22 18:24:56.945750616 +0000
    Modify: 2018-10-22 18:24:56.945750616 +0000
    Change: 2018-10-22 18:24:56.957750616 +0000
     Birth: -
  "
  desc  "fix", "
    Run the following commands to set ownership and permissions on the private
SSH host key files

    ```
    # find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root
{} \\;
    ```

    ```
    # find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \\;
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-3 (3)"]
  tag cis_level: 1
  tag cis_controls: ["14.6"]
  tag cis_rid: "5.2.2"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  if inspec.directory('/etc/ssh').exist?
    find_command = command("find /etc/ssh -xdev -type f -name 'ssh_host_*_key'").stdout.lines
    unless find_command.empty?
      find_command.each do |key_file|
        describe file(key_file.chomp) do
          it { should be_file }
          it { should be_owned_by 'root' }
          it { should be_grouped_into 'root' }
          it { should_not be_more_permissive_than('0600') }
        end
      end
    else
      descibe "No 'ssh_host_*_key' files were found in '/etc/ssh'" do 
        skip "You must validate this control manually or correct your sshd config"
      end
    end
  else
    descibe "'/etc/ssh' does not seem to exist, you must check this control by hand" do
      skip '/etc/ssh did not exist, please check this control by hand'
    end
  end
end
