use strict;
use warnings;

use Test::More;
use Class::Load 'try_load_class';
use Dancer2::Plugin::Auth::Extensible::Test;

BEGIN {
    $ENV{DANCER_CONFDIR}     = 't/lib';
    $ENV{DANCER_ENVIRONMENT} = 'provider-dbic';
}

{
    package TestApp;
    use Path::Tiny;
    use Dancer2;
    use Dancer2::Plugin::DBIC;
    use Dancer2::Plugin::Auth::Extensible;
    use Dancer2::Plugin::Auth::Extensible::Test::App;

    my $schema1 = schema('schema1');
    $schema1->deploy;
    my $schema2 = schema('schema2');
    $schema2->deploy;

    $schema1->resultset('User')->populate(
        [
            [ 'id', 'username', 'password', 'name' ],
            [ 1,    'dave',     'beer',     'David Precious' ],
            [ 2,    'bob',      'cider',    'Bob Smith' ],
        ]
    );

    $schema1->resultset('Role')->populate(
        [
            [ 'id', 'role' ],
            [ 1,    'BeerDrinker' ],
            [ 2,    'Motorcyclist' ],
            [ 3,    'CiderDrinker' ],
        ]
    );

    $schema1->resultset('UserRole')
      ->populate( [ [ 'user_id', 'role_id' ], [ 1, 1 ], [ 1, 2 ], [ 2, 3 ], ] );

    $schema2->resultset('User')->populate(
        [
            [ 'id', 'username', 'password' ],
            [ 1,    'burt',     'bacharach' ],
            [ 2, 'hashedpassword', '{SSHA}+2u1HpOU7ak6iBR6JlpICpAUvSpA/zBM' ],
        ]
    );
}

my $app = Dancer2->runner->psgi_app;
is( ref $app, 'CODE', 'Got app' );

Dancer2::Plugin::Auth::Extensible::Test::testme($app);

done_testing;
