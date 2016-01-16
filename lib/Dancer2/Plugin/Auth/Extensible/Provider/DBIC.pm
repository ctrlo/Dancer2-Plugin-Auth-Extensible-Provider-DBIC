package Dancer2::Plugin::Auth::Extensible::Provider::DBIC;

use strict;
use base 'Dancer2::Plugin::Auth::Extensible::Provider::Base';
use DBIx::Class::ResultClass::HashRefInflator;
use Lingua::EN::Inflect::Phrase;
use String::CamelCase qw(camelize);

our $VERSION = '0.401';

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
                    users_username_column: username
                    users_password_column: password
                    roles_role_column: role

                    # This plugin supports the DPAE record_lastlogin functionality.
                    # Optionally set the column name:
                    users_lastlogin_column: lastlogin

                    # Optionally set columns for user_password functionality in
                    # Dancer2::Plugin::Auth::Extensible
                    users_pwresetcode_column: pw_reset_code
                    users_pwchanged_column:   # Time of reset column. No default.

                    # Days after which passwords expire. See logged_in_user_password_expired
                    # functionality in Dancer2::Plugin::Auth::Extensible
                    password_expiry_days:       # No default

                    # Optionally set the name of the DBIC schema
                    schema_name: myschema

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

                    # Optionally specify the algorithm when encrypting new passwords
                    encryption_algorithm: SHA-512

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

=item schema_name

Specfies the name of the L<Dancer2::Plugin::DBIC> schema to use. If not
specified, will default in the same manner as the DBIC plugin.

=item user_valid_conditions

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

=back

=head1 SUGGESTED SCHEMA

See the L<Dancer2::Plugin::Auth::Extensible::Provider::Database> documentation
for an example schema.

=cut

# Override ::Base->new, as we need to store DB schema
sub new {
    my ($class, $realm_settings, $dsl) = @_;

    if ( $dsl->app->can('with_plugin') ) {
        # plugin2
        $dsl->app->with_plugin('Dancer2::Plugin::DBIC')
          or die "Failed to load Dancer2::Plugin::DBIC";
    }
    else {
        # old bad world
        die "No schema method in app. Did you load Dancer2::Plugin::DBIC before Dancer2::Plugin::Auth::Extensible?"
          unless $dsl->can('schema');
    }

    # Grab a handle to the Plugin::DBIC schema
    my $schema = $realm_settings->{schema_name}
               ? $dsl->schema($realm_settings->{schema_name})
               : $dsl->schema;

    # Set default values
    $realm_settings->{users_table}              ||= 'users';
    $realm_settings->{users_username_column}    ||= 'username';
    $realm_settings->{users_lastlogin_column}   ||= 'lastlogin';
    $realm_settings->{user_valid_conditions}    ||= {};
    $realm_settings->{users_password_column}    ||= 'password';
    $realm_settings->{roles_table}              ||= 'roles';
    $realm_settings->{user_roles_table}         ||= 'user_roles';
    $realm_settings->{roles_role_column}        ||= 'role';
    $realm_settings->{users_pwresetcode_column} ||= 'pw_reset_code';

    my $self = {
        realm_settings => $realm_settings,
        dsl_local      => $dsl,
        schema         => $schema,
    };
    return bless $self => $class;
}

# Returns a DBIC rset for the user
sub _user_rset {
    my ($self, $column, $value, $options) = @_;
    my $settings              = $self->realm_settings;
    my $users_table           = $settings->{users_table};
    my $username_column       = $settings->{users_username_column};
    my $user_valid_conditions = $settings->{user_valid_conditions};

    my $search_column = $column eq 'username'
                      ? $username_column
                      : $column eq 'pw_reset_code'
                      ? $settings->{users_pwresetcode_column}
                      : $column;

    # Search based on standard username search, plus any additional
    # conditions in ignore_user
    my $search = { %$user_valid_conditions, $search_column => $value };

    # Look up the user
    $self->_schema->resultset(camelize $users_table)->search($search, $options);
}

sub _dsl_local { shift->{dsl_local} };

sub _schema {
    # Make sure we have an existing DBIC schema. Should have been
    # created on plugin load
    shift->{schema} or die "No DBIC schema available";
}

sub authenticate_user {
    my ($self, $username, $password, %options) = @_;

    # Look up the user:
    my $user = $self->get_user_details($username);
    return unless $user;

    # OK, we found a user, let match_password (from our base class) take care of
    # working out if the password is correct
    my $settings        = $self->realm_settings;
    my $password_column = $settings->{users_password_column};
    if (my $match = $self->match_password($password, $user->{$password_column})) {
        if ($options{lastlogin}) {
            if (my $lastlogin = $user->{lastlogin}) {
                my $db_parser = $self->_schema->storage->datetime_parser;
                $lastlogin    = $db_parser->parse_datetime($lastlogin);
                $self->_dsl_local->app->session->write($options{lastlogin} => $lastlogin);
            }
            $self->set_user_details(
                $username,
                $self->realm_settings->{users_lastlogin_column} => DateTime->now,
            );
        }
        return $match;
    }
    return; # Make sure we return nothing
}

sub set_user_password {
    my ($self, $username, $password) = @_;
    my $settings        = $self->realm_settings;
    my $algorithm       = $settings->{encryption_algorithm};
    my $encrypted       = $self->encrypt_password($password, $algorithm);
    my $password_column = $settings->{users_password_column};
    my %update          = ($password_column => $encrypted);
    if (my $pwchanged = $settings->{users_pwchanged_column}) {
        $update{$pwchanged} = DateTime->now;
    }
    $self->set_user_details($username, %update);
}

# Return details about the user.  The user's row in the users table will be
# fetched and all columns returned as a hashref.
sub get_user_details {
    my ($self, $username) = @_;
    return unless defined $username;

    # Look up the user
    my $users_rs = $self->_user_rset(username => $username);

    # Inflate to a hashref, otherwise it's returned as a DBIC rset
    $users_rs->result_class('DBIx::Class::ResultClass::HashRefInflator');
    my ($user) = $users_rs->all;
    
    if (!$user) {
        $self->_dsl_local->debug("No such user $username");
        return;
    } else {
        my $settings = $self->realm_settings;
        if (my $pwchanged = $settings->{users_pwchanged_column}) {
            # Convert to DateTime object
            my $db_parser = $self->_schema->storage->datetime_parser;
            $user->{$pwchanged} = $db_parser->parse_datetime($user->{$pwchanged})
                if $user->{$pwchanged};
        }
        if (my $roles_key = $settings->{roles_key}) {
            my @roles = @{$self->get_user_roles($username)};
            my %roles = map { $_ => 1 } @roles;
            $user->{$roles_key} = \%roles;
        }
        return $user;
    }
}

# Find a user based on a password reset code
sub get_user_by_code {
    my ($self, $code) = @_;

    my $username_column = $self->realm_settings->{users_username_column};
    my $users_rs        = $self->_user_rset(pw_reset_code => $code);
    my ($user)          = $users_rs->all;
    return unless $user;
    $user->$username_column;
}

sub create_user {
    my ($self, %user) = @_;
    my $settings        = $self->realm_settings;
    my $users_table     = $settings->{users_table};
    my $username_column = $settings->{users_username_column};
    my $username        = $user{username}
        or die "Username needs to be specified for create_user";
    $self->_schema->resultset(camelize $users_table)->create({
        $username_column => $username
    });
    $self->set_user_details($username, %user);
}

# Update a user. Username is provided in the update details
sub set_user_details {
    my ($self, $username, %update) = @_;

    die "Username to update needs to be specified"
        unless $username;

    my $settings = $self->realm_settings;

    # Look up the user
    my ($user) = $self->_user_rset(username => $username)->all;
    $user or return;

    # Are we expecting a user_roles key?
    if (my $roles_key = $self->realm_settings->{roles_key}) {
        if (my $new_roles = delete $update{$roles_key}) {

            my $users_table           = $settings->{users_table};
            my $roles_table           = $settings->{roles_table};
            my $user_roles_table      = $settings->{user_roles_table};
            my $roles_role_column     = $settings->{roles_role_column};
            my $users_username_column = $settings->{users_username_column};

            my @all_roles      = $self->_schema->resultset(camelize $roles_table)->all;
            my %existing_roles = map { $_ => 1 } @{$self->get_user_roles($username)};

            foreach my $role (@all_roles) {
                my $role_name = $role->$roles_role_column;
                if ($new_roles->{$role_name} && !$existing_roles{$role_name}) {
                    # Needs to be added
                    $self->_schema->resultset(camelize $user_roles_table)->create({
                        $users_table => {
                            $users_username_column => $username,
                            %{$settings->{user_valid_conditions}}
                        },
                        $roles_table => { $roles_role_column => $role_name },
                    });
                }
                elsif (!$new_roles->{$role_name} && $existing_roles{$role_name}) {
                    # Needs to be removed
                    $self->_schema->resultset(camelize $user_roles_table)->search({
                        "$users_table.$users_username_column" => $username,
                        "$roles_table.$roles_role_column"     => $role_name,
                    },{
                        join => [ $users_table, $roles_table ],
                    })->delete;
                }
            }
        }
    }

    # Move password reset code between keys if required
    if (my $users_pwresetcode_column = $settings->{users_pwresetcode_column}) {
        if (exists $update{pw_reset_code}) {
            my $pw_reset_code = delete $update{pw_reset_code};
            $update{$users_pwresetcode_column} = $pw_reset_code;
        }
    }
    $user->update({%update});
    # Update $username if it was submitted in update
    $username = $update{username} if $update{username};
    return $self->get_user_details($username);
}

sub get_user_roles {
    my ($self, $username) = @_;

    my $settings          = $self->realm_settings;
    my $roles_table       = $settings->{roles_table};
    my $user_roles_table  = $settings->{user_roles_table};
    my $roles_role_column = $settings->{roles_role_column};
    $user_roles_table     = Lingua::EN::Inflect::Phrase::to_PL($user_roles_table);

    my $options = { prefetch => { $user_roles_table => $roles_table } };
    my ($user) = $self->_user_rset(username => $username, $options)->all;
    if (!$user) {
        $self->_dsl_local->debug("No such user $username when looking for roles");
        return;
    }

    my @roles;
    foreach my $ur ($user->$user_roles_table)
    {
        my $role = $ur->$roles_table->$roles_role_column;
        push @roles, $role;
    }

    \@roles;
}

sub password_expired {
    my ($self, $user) = @_;
    my $settings = $self->realm_settings;
    my $expiry   = $settings->{password_expiry_days}
        or return 0; # No expiry set
    if (my $pwchanged = $settings->{users_pwchanged_column}) {
        my $last_changed = $user->{$pwchanged}
            or return 1; # If not changed then report expired
        my $duration     = $last_changed->delta_days(DateTime->now);
        $duration->in_units('days') > $expiry ? 1 : 0;
    } else {
        die "users_pwchanged_column not configured";
    }
}

1;
