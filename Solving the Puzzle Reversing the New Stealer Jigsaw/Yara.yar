rule Stealer_Detection {
    meta:
        description = "Detects executables referencing various clients, such as web browsers, email and collaboration clients, and messaging apps. Observed in information stealers."
        author = "ThreatMon"
    strings:
        // Browsers
        $browser1 = "Google\\Chrome\\User Data" nocase ascii wide
        $browser2 = "Mozilla Thunderbird\\nss3.dll" ascii wide
        $browser3 = "Telegram Desktop\\tdata" ascii wide
        $browser4 = "Steam\\config" ascii wide
        $browser5 = "Microsoft\\Windows Mail\\account{" ascii wide
        $browser6 = "Sputnik\\User Data" nocase ascii wide
        $browser7 = "Yandex\\YandexBrowser\\User Data" nocase ascii wide
        $browser8 = "Mail.Ru\\Atom\\User Data" nocase ascii wide
        $browser9 = "Vivaldi\\User Data" nocase ascii wide
        $browser10 = "Opera Mail\\Opera Mail\\wand.dat" ascii wide

        // Confidential Data Stores
        $confidential_data1 = "key3.db" nocase ascii wide
        $confidential_data2 = "cert8.db" nocase ascii wide
        $confidential_data3 = "wallet.dat" nocase ascii wide
        $confidential_data4 = "logins.json" nocase ascii wide
        $confidential_data5 = "account.cfn" nocase ascii wide
        $confidential_data6 = "wand.dat" nocase ascii wide
        $confidential_data7 = "Opera Software\\" nocase ascii wide

        // Messaging Clients
        $messaging1 = "Microsoft\\Windows Live Mail"  nocase ascii wide
        $messaging2 = "Discord\\Local Storage\\leveldb" ascii wide
        $messaging3 = "MailSpring\\" ascii wide
        $messaging4 = "Psi+\\accounts.xml" ascii wide
        $messaging5 = "Microsoft\\Office\\Outlook\\OMI Account Manager\\Accounts" ascii wide
        $messaging6 = "SeaMonkey\\nss3.dll" ascii wide
        $messaging7 = "Pocomail\\accounts.ini" ascii wide
        $messaging8 = "Psi\\profiles" ascii wide
        $messaging9 = "Microsoft\\Office\\17.0\\Outlook\\Profiles\\Outlook" ascii wide
        $messaging10 = "Steam\\userdata\\" ascii wide
        $messaging11 = "Flock\\nss3.dll" ascii wide
        $messaging12 = "BlackHawk\\User Data" nocase ascii wide
        $messaging13 = "QQBrowser\\User Data" nocase ascii wide
        $messaging14 = "Chromodo\\User Data" nocase ascii wide

    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0xfacf) and
        3 of ($browser1, $browser2, $browser3, $browser4, $browser5, $browser6, $browser7, $browser8, $browser9, $browser10,
             $confidential_data1, $confidential_data2, $confidential_data3, $confidential_data4, $confidential_data5, $confidential_data6, $confidential_data7,
             $messaging1, $messaging2, $messaging3, $messaging4, $messaging5, $messaging6, $messaging7, $messaging8, $messaging9, $messaging10, $messaging11,
             $messaging12, $messaging13, $messaging14)
}
