file(REMOVE_RECURSE
  "liblongfellow_static.a"
  "liblongfellow_static.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang CXX)
  include(CMakeFiles/longfellow_static.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
