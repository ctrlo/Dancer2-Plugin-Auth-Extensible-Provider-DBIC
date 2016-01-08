package t::lib::Schema::Result::Role;
use base qw/DBIx::Class::Core/;
__PACKAGE__->table('role');
__PACKAGE__->add_columns(
    id   => { data_type => 'integer' },
    role => { data_type => 'varchar', size => 32 },
);
__PACKAGE__->set_primary_key('id');
__PACKAGE__->has_many(
    user_roles => "t::lib::Schema::Result::UserRole",
    "role_id"
);
1;
