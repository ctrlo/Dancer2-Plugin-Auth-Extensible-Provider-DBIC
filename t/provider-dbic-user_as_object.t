use strict;
use warnings;

use Test::More;

BEGIN {
    $ENV{DANCER_ENVDIR}      = 't/environments';
    $ENV{DANCER_ENVIRONMENT} = 'object';
}

use Dancer2::Plugin::Auth::Extensible::Test;

{
    package TestApp;
    use Dancer2;
    use Dancer2::Plugin::DBIC;
    use Dancer2::Plugin::Auth::Extensible 0.613;
    use Dancer2::Plugin::Auth::Extensible::Test::App;

    my $schema1 = schema('schema1');
    $schema1->deploy;
    my $schema2 = schema('schema2');
    $schema2->deploy;
    my $schema3 = schema('schema3');
    $schema3->deploy;
}

my $app = Dancer2->runner->psgi_app;
is( ref $app, 'CODE', 'Got app' );

Dancer2::Plugin::Auth::Extensible::Test::testme( $app, 'create_user',
    'update_user');

done_testing;
