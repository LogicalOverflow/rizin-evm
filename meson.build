project('rizin-evm', 'c')

deps = [dependency('rz_analysis')]
incdir = include_directories('include')

rzdir = run_command(
  'rizin', '-H', 'RZ_USER_PLUGINS', check: true
).stdout().strip()

shared_library('asm_evm', 'src/asm/asm_evm.c',
               name_prefix : '',
               include_directories : incdir,
               dependencies : deps,
               install_dir : rzdir,
               install: true)

shared_library('analysis_evm', 'src/analysis/analysis_evm.c',
               name_prefix : '',
               include_directories : incdir,
               dependencies : deps,
               install_dir : rzdir,
               install: true)
