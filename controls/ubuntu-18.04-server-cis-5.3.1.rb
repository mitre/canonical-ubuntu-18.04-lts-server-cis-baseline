# encoding: UTF-8

control "C-5.3.1" do
  title "Ensure password creation requirements are configured"
  desc  "The `pam_pwquality.so` module checks the strength of passwords. It
performs checks such as making sure a password is not a dictionary word, it is
a certain length, contains a mix of characters (e.g. alphabet, numeric, other)
and more. The following are definitions of the `pam_pwquality.so` options.

    The following options are set in the `/etc/security/pwquality.conf` file:

    Password Length:

    - `minlen = 14` - password must be 14 characters or more

    Password complexity:

    - `minclass = 4` - The minimum number of required classes of characters for
the new password (digits, uppercase, lowercase, others)

    **OR**

    - `dcredit = -1` - provide at least one digit
    - `ucredit = -1` - provide at least one uppercase character
    - `ocredit = -1` - provide at least one special character
    - `lcredit = -1` - provide at least one lowercase character

    The following is st in the `/etc/pam.d/common-password` file

    - `retry=3` - Allow 3 tries before sending back a failure.

    The settings shown above are one possible policy. Alter these values to
conform to your own organization's password policies.
  "
  desc  "rationale", "Strong passwords protect systems from being hacked
through brute force methods."
  desc  "check", "
    Verify password creation requirements conform to organization policy.

    Run the following command to verify the minimum password length is 14 or
more characters.

    ```
    # grep '^\\s*minlen\\s*' /etc/security/pwquality.conf

    minlen = 14
    ```

    Run one of the following commands to verify the required password
complexity:

    ```
    # grep '^\\s*minclass\\s*' /etc/security/pwquality.conf

    minclass = 4
    ```

    **OR**

    ```
    # grep -E '^\\s*[duol]credit\\s*' /etc/security/pwquality.conf

    dcredit = -1
    ucredit = -1
    lcredit = -1
    ocredit = -1
    ```

    Run the following command to verify the number of attempts allowed before
sending back a failure are no more than 3

    ```
    # grep -E
'^\\s*password\\s+(requisite|required)\\s+pam_pwquality\\.so\\s+(\\S+\\s+)*retry=[1-3]\\s*(\\s+\\S+\\s*)*(\\s+#.*)?$'
/etc/pam.d/common-password

    password requisite pam_pwquality.so retry=3
    ```
  "
  desc  "fix", "
    Run the following command to install the pam_pwquality module:

    ```
    apt install libpam-pwquality
    ```

    Edit the file `/etc/security/pwquality.conf` and add or modify the
following line for password length to conform to site policy
    ```
    minlen = 14
    ```

    Edit the file /etc/security/pwquality.conf and add or modify the following
line for password complexity to conform to site policy

    ```
    minclass = 4
    ```

    **OR**

    ```
    dcredit = -1
    ucredit = -1
    ocredit = -1
    lcredit = -1
    ```

    Edit the `/etc/pam.d/common-password` file to include the appropriate
options for `pam_pwquality.so` and to conform to site policy:

    ```
    password requisite pam_pwquality.so retry=3
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
  tag nist: ["IA-5 (1)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["4.4", "Rev_7"]
  tag cis_rid: "5.3.1"
end
