# encoding: UTF-8

control "C-2.2.7" do
  title "Ensure NFS and RPC are not enabled"
  desc  "The Network File System (NFS) is one of the first and most widely
distributed file systems in the UNIX environment. It provides the ability for
systems to mount file systems of other servers through the network."
  desc  "rationale", "If the system does not export NFS shares or act as an NFS
client, it is recommended that these services be disabled to reduce the remote
attack surface."
  desc  "check", "
    Run the following command to verify `nfs` is not enabled:

    ```
    # systemctl is-enabled nfs-server

    disabled
    ```

    Verify result is not \"enabled\".

    Run the following command to verify `rpcbind` is not enabled:

    ```
    # systemctl is-enabled rpcbind

    disabled
    ```

    Verify result is not \"enabled\".
  "
  desc  "fix", "
    Run the following commands to disable `nfs` and `rpcbind`:

    ```
    # systemctl --now disable nfs-server

    # systemctl --now disable rpcbind
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
  tag cis_rid: "2.2.7"

  if package('nfs-kernel-server').installed? || package('nfs-ganesha').installed?
      describe service('nfs-kernel-server') do
        it { should_not be_enabled }
        it { should_not be_running }
      end
      describe service('nfs-ganesha') do
        it { should_not be_enabled }
        it { should_not be_running }
      end
    describe service('rpcbind') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  else
    impact 0.0
    describe "An NFS and RPC Server packages are not installed" do
      skip "An NFS and RPC Server packages are not installed, this control is Not Applicable."
    end
  end
end


