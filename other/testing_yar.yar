rule test {
   meta:
      description = "testing"     
      score = 60
   strings:
      $ = "Framework" ascii wide nocase
   condition:   
     1 of them
}
