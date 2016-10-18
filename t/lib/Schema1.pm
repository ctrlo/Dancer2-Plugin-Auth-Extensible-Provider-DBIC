package t::lib::Schema1;
use base 'DBIx::Class::Schema';
__PACKAGE__->load_namespaces;
sub deploy {
    my $self = shift;
    $self->next::method(@_);
    
    $self->resultset('User')->populate(
        [
            [ 'id', 'username', 'password', 'name' ],
            [ 1,    'dave',     'beer',     'David Precious' ],
            [ 2,    'bob',      'cider',    'Bob Smith' ],
            [ 3,    'mark',     'wantscider',    'Update here' ],
        ]
    );

    $self->resultset('Role')->populate(
        [
            [ 'id', 'role' ],
            [ 1,    'BeerDrinker' ],
            [ 2,    'Motorcyclist' ],
            [ 3,    'CiderDrinker' ],
        ]
    );

    $self->resultset('UserRole')
      ->populate( [ [ 'user_id', 'role_id' ], [ 1, 1 ], [ 1, 2 ], [ 2, 3 ], ] );
}

1;
