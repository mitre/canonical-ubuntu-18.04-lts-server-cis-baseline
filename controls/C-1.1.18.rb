# encoding: UTF-8

control "C-1.1.18" do
  title "Ensure nodev option set on removable media partitions"
  desc  "The `nodev` mount option specifies that the filesystem cannot contain
special devices."
  desc  "rationale", "Removable media containing character and block special
devices could be used to circumvent security controls by allowing non-root
users to access sensitive device files such as `/dev/kmem` or the raw disk
partitions."
  desc  "check", "
    Run the following command and verify that the `nodev` option is set on all
removable media partitions.

    ```
    # mount
    ```
  "
  desc "fix", "Edit the `/etc/fstab` file and add `nodev` to the fourth field
(mounting options) of all removable media partitions. Look for entries that
have mount points that contain words such as floppy or cdrom. See the
`fstab(5)` manual page for more information."
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
  tag cis_rid: "1.1.18"


  mounts = command('mount').stdout.strip.split("\n").
      map do |d|
    split_mounts = d.split(%r{\s+})
    options = split_mounts[-1].match(%r{\((.*)\)$}).captures.first.split(',')
    dev_file = file(split_mounts[0])
    dev_link = dev_file.symlink? ? dev_file.link_path : dev_file.path
    {'dev'=>split_mounts[0], 'link'=>dev_link, 'mount'=>split_mounts[2], 'options'=>options}
  end

  dev_mounts = mounts.
      select { |mnt| mnt['dev'].start_with? '/' and !mnt['dev'].start_with? '//' }.
      map do |mnt|
    # https://unix.stackexchange.com/a/308724
    partition = ['/sys/class/block', String(mnt['link']).sub(%r{^/dev/}, ''), 'partition'].join('/')
    if file(partition).exist?
      # root_dev = command('basename "$(readlink -f "/sys/class/block/sda1/..")"').stdout.strip
      root_dev = mount('/').device()
    else
      mnt['root_dev'] = mnt['link']
    end
    mnt
  end

  removable_mounts = dev_mounts.select do |mnt|
    removable = ['/sys/block', String(mnt['root_dev']).sub(%r{^/dev/}, ''), 'removable'].join('/')
    #file(removable).content.strip == '1'
    file(removable).file.stat.length > 0
  end

  if removable_mounts.empty?
    describe "Removable mounted devices" do
      subject { removable_mounts }
      it { should be_empty }
    end
  else
    removable_mounts.each do |mnt|
      # describe "Mount #{mnt['mount']} options" do
      #   subject { mnt['options'] }
      #   it { should include 'nodev' }
      # end
      describe mount(mnt) do
        it { should be_mounted }
        its('options') { should include 'nosuid' }
      end
    end
  end

  # /bin/mount | /bin/grep -P 'on[\\s]+/dev/(floppy|cdrom|corder|mmcblk)'"

end
