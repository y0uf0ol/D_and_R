rule testing_af {
    meta:
        test = "yoink"
    strings:
        $ = "Visual"
    condition:
        any of them
}
