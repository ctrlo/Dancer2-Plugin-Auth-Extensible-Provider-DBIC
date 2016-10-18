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
    use Dancer2::Plugin::Auth::Extensible 0.501;
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
            [ 3,    'mark',     'wantscider',    'Update here' ],
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

    $schema2->resultset('Myuser')->populate(
        [
            [ 'id', 'myusername', 'mypassword' ],
            [ 1,    'burt',     'bacharach' ],
            [ 2, 'hashedpassword', '{SSHA}+2u1HpOU7ak6iBR6JlpICpAUvSpA/zBM' ],
            [ 3,    'mark',     'wantscider' ],
        ]
    );
    $schema2->resultset('Myrole')->populate(
        [
            [ 'id', 'rolename' ],
            [ 1,    'BeerDrinker' ],
            [ 2,    'Motorcyclist' ],
            [ 3,    'CiderDrinker' ],
        ]
    );

}

my $app = Dancer2->runner->psgi_app;
is( ref $app, 'CODE', 'Got app' );

Dancer2::Plugin::Auth::Extensible::Test::testme($app, 'create_user', 'update_user');

done_testing;
