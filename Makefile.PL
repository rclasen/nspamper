use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'nspamper',
    'VERSION_FROM'	=> 'nspamper', # finds $VERSION
    'PREREQ_PM'		=> {
	# update debian/control, too!
    	'Net::DNS'	=> 0,
    	}, # e.g., Module::Name => 1.1
    'EXE_FILES'		=> [qw(
    	nspamper
	nspamper-change
	ddns
	dyn2nsup
    )],
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'nspamper', # retrieve abstract from module
       AUTHOR     => 'Rainer Clasen <rc@zuto.de>') : ()),
);
