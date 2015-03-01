package Dancer2::Plugin::Auth::Extensible::Provider::DBIC;

use strict;
use base 'Dancer2::Plugin::Auth::Extensible::Provider::Base';
use DBIx::Class::ResultClass::HashRefInflator;
use Lingua::EN::Inflect::Phrase;
use String::CamelCase qw(camelize);

our $VERSION = '0.306';

=head1 NAME 

Dancer2::Plugin::Auth::Extensible::Provider::DBIC - authenticate via the
L<Dancer2::Plugin::DBIC> plugin


=head1 DESCRIPTION

This class is an authentication provider designed to authenticate users against
a database, using L<Dancer2::Plugin::DBIC> to access a database.

See L<Dancer2::Plugin::DBIC> for how to configure a database connection
appropriately; see the L</CONFIGURATION> section below for how to configure this
authentication provider with database details.

See L<Dancer2::Plugin::Auth::Extensible> for details on how to use the
authentication framework.


=head1 CONFIGURATION

This provider tries to use sensible defaults, in the same manner as
L<Dancer2::Plugin::Auth::Extensible::Provider::Database>, so you may not need
to provide much configuration if your database tables look similar to those.

The most basic configuration, assuming defaults for all options, and defining a
single authentication realm named 'users':

    plugins:
        Auth::Extensible:
            realms:
                users:
                    provider: 'DBIC'

You would still need to have provided suitable database connection details to
L<Dancer2::Plugin::DBIC>, of course;  see the docs for that plugin for full
details, but it could be as simple as, e.g.:

    plugins:
        Auth::Extensible:
            realms:
                users:
                    provider: 'DBIC'
        DBIC:
            default:
                dsn: dbi:mysql:database=mydb;host=localhost
                schema_class: MyApp::Schema
                user: user
                pass: secret

A full example showing all options:

    plugins:
        Auth::Extensible:
            realms:
                users:
                    provider: 'DBIC'

                    # optionally specify names of tables if they're not the defaults
                    # (defaults are 'users', 'roles' and 'user_roles')
                    users_table: 'users'
                    roles_table: 'roles'
                    user_roles_table: 'user_roles'

                    # optionally set the column names
                    users_username_column: 'username'
                    users_password_column: 'password'
                    roles_role_column: 'role'

                    # Optionally set additional conditions when searching for the
                    # user in the database. These are the same format as required
                    # by DBIC, and are passed directly to the DBIC resultset search
                    user_valid_conditions:
                        deleted: 0
                        account_request:
                            "<": 1

                    # Optionally specify a key for the user's roles to be returned in.
                    # Roles will be returned as role_name => 1 hashref pairs
                    roles_key: roles

=over

=item users_table

Specifies the database table that the users are stored in. This will be camelized.

=item roles_table

Specifies the database table that the roles are stored in. This will be camelized.

=item user_roles_table

Specifies the database table that holds the many-to-many relationship information
between users and roles. It is assumed that the relationship is configured in
the DBIC schema, such that a user has many entries in the user_roles table, and
that each of those has one role. This table name will be pluralized.

=item users_username_column

Specifies the column name of the username column in the users table

=item users_password_column

Specifies the column name of the password column in the users table

=item roles_role_column

Specifies the column name of the role name column in the roles table

=item user_valid_condition

Specifies additional search parameters when looking up a user in the users table.
For example, you might want to exclude any account this is flagged as deleted
or disabled.

The value of this parameter will be passed directly to DBIC as a search condition.
It is therefore possible to nest parameters and use different operators for the
condition. See the example config above for an example.

=item roles_key

Specifies a key for the returned user hash to also return the user's roles in.
The value of this key will contain a hash ref, which will contain each
permission with a value of 1. In your code you might then have:

    my $user = logged_in_user;
    return foo_bar($user);

    sub foo_bar
    {   my $user = shift;
        if ($user->{roles}->{beer_drinker}) {
           ...
        }
    }

This isn't intended to replace the L<Dancer2::Plugin::Auth::Extensible/user_has_role>
keyword. Instead it is intended to make it easier to access a user's roles if the
user hash is being passed around (without requiring access to the user_has_role
keyword in other modules).

=head1 SUGGESTED SCHEMA

See the L<Dancer2::Plugin::Auth::Extensible::Provider::Database> documentation
for an example schema.

=cut

# Override ::Base->new, as we need to store DB schema
sub new {
    my ($class, $realm_settings, $dsl) = @_;

    # Grab a handle to the Plugin::DBIC schema
    die "No schema method in app. Did you load DBIC::Plugin::DBIC before DBIC::Plugin::Auth::Extensible?"
        unless $dsl->can('schema');
    my $schema = $dsl->schema;

    my $self = {
        realm_settings => $realm_settings,
        dsl_local      => $dsl,
        schema         => $schema,
    };
    return bless $self => $class;
}

# Returns a DBIC rset for the user
sub _user {
    my ($self, $username) = @_;
    my $settings              = $self->realm_settings;
    my $users_table           = $settings->{users_table}           || 'users';
    my $username_column       = $settings->{users_username_column} || 'username';
    my $user_valid_conditions = $settings->{user_valid_conditions} || {};

    # Search based on standard username search, plus any additional
    # conditions in ignore_user
    my $search = { %$user_valid_conditions, $username_column => $username };

    # Look up the user
    $self->_schema->resultset(camelize $users_table)->search($search);
}

sub _dsl_local { shift->{dsl_local} };

sub _schema {
    # Make sure we have an existing DBIC schema. Should have been
    # created on plugin load
    shift->{schema} or die "No DBIC schema available";
}

sub authenticate_user {
    my ($self, $username, $password) = @_;

    # Look up the user:
    my $user = $self->get_user_details($username);
    return unless $user;

    # OK, we found a user, let match_password (from our base class) take care of
    # working out if the password is correct
    my $settings        = $self->realm_settings;
    my $password_column = $settings->{users_password_column} || 'password';
    return $self->match_password($password, $user->{$password_column});
}


# Return details about the user.  The user's row in the users table will be
# fetched and all columns returned as a hashref.
sub get_user_details {
    my ($self, $username) = @_;
    return unless defined $username;

    # Look up the user
    my $users_rs = $self->_user($username);

    # Inflate to a hashref, otherwise it's returned as a DBIC rset
    $users_rs->result_class('DBIx::Class::ResultClass::HashRefInflator');
    my ($user) = $users_rs->all;
    
    if (!$user) {
        $self->_dsl_local->debug("No such user $username");
        return;
    } else {
        if (my $roles_key = $self->realm_settings->{roles_key}) {
            my @roles = @{$self->get_user_roles($username)};
            my %roles = map { $_ => 1 } @roles;
            $user->{$roles_key} = \%roles;
        }
        return $user;
    }
}

sub get_user_roles {
    my ($self, $username) = @_;

    my ($user) = $self->_user($username)->all;
    if (!$user) {
        $self->_dsl_local->debug("No such user $username when looking for roles");
        return;
    }

    my $settings          = $self->realm_settings;
    my $roles_table       = $settings->{roles_table}       || 'roles';
    my $user_roles_table  = $settings->{user_roles_table}  || 'user_roles';
    my $roles_role_column = $settings->{roles_role_column} || 'role';
    $user_roles_table     = Lingua::EN::Inflect::Phrase::to_PL($user_roles_table);

    my @roles;
    foreach my $ur ($user->$user_roles_table)
    {
        my $role = $ur->$roles_table->$roles_role_column;
        push @roles, $role;
    }

    \@roles;
}

1;
