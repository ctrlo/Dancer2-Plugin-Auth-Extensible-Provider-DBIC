use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Dancer2::Plugin::Auth::Extensible::Provider::DBIC',
    AUTHOR              => q{Andy Beverley <andy@andybev.com>},
    VERSION_FROM        => 'lib/Dancer2/Plugin/Auth/Extensible/Provider/DBIC.pm',
    ABSTRACT_FROM       => 'lib/Dancer2/Plugin/Auth/Extensible/Provider/DBIC.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More'  => 0, # For future tests?
        'Dancer2::Plugin::DBIC' => 0,
        'Dancer2::Plugin::Auth::Extensible' => 0.304,
        'DBIx::Class::ResultClass::HashRefInflator' => 0,
        'Lingua::EN::Inflect::Phrase' => 0,
        'String::CamelCase' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Dancer2-Plugin-Auth-Extensible-*' },
    META_MERGE => {
        resources => {
            repository => 'https://github.com/ctrlo/Dancer2-Plugin-Auth-Extensible-Provider-DBIC',
            bugtracker => 'https://github.com/ctrlo/Dancer2-Plugin-Auth-Extensible-Provider-DBIC/issues',
            homepage   => 'https://github.com/ctrlo/Dancer2-Plugin-Auth-Extensible-Provider-DBIC/',
        },
    },

);
