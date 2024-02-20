rule {
    meta:
        test = "yoink"
    strings:
        $ = "Visual"
    condition:
        any of them
}
