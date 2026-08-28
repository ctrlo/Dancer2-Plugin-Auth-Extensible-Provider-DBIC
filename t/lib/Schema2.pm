package t::lib::Schema2;
use base 'DBIx::Class::Schema';
__PACKAGE__->load_namespaces;
sub deploy {
    my $self = shift;
    $self->next::method(@_);

    $self->resultset('Myuser')->populate(
        [
            [ 'id', 'myusername', 'mypassword' ],
            [ 1,    'burt',     'bacharach' ],
            [ 2, 'hashedpassword', '{SSHA}iFLZs/A/YYTB13U60mqNdMqD6jElkY7V' ],
            [ 3,    'mark',     'wantscider' ],
        ]
    );
    $self->resultset('Myrole')->populate(
        [
            [ 'id', 'rolename' ],
            [ 1,    'BeerDrinker' ],
            [ 2,    'Motorcyclist' ],
            [ 3,    'CiderDrinker' ],
        ]
    );
}

1;
