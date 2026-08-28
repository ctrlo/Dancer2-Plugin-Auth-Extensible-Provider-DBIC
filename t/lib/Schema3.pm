package t::lib::Schema3;
use base 'DBIx::Class::Schema';
__PACKAGE__->load_namespaces;
sub deploy {
    my $self = shift;
    $self->next::method(@_);
    
    $self->resultset('User')->populate(
        [
            [ 'id', 'username', 'password', 'name' ],
            [ 1,    'bananarepublic',     'whatever',     'Banana' ],
            [ 2, 'hashedpassword',     '$5$rounds=656000$bs1bOYFalsL9WzJP$DdpfTVf5Rumd2ZYuHTvz1ePQaAh1iy36OIXP7Hgjzs3', 'hashedpassword' ],
            [ 3, 'mark', 'wantscider', 'Update here' ],
        ]
    );

    $self->resultset('Role')->populate(
        [
            [ 'id', 'role' ],
            [ 1,    'CiderDrinker' ],
        ]
    );
}

1;
