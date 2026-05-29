INSERT INTO roles (name) VALUES ('admin'), ('moderator'), ('user');

INSERT INTO permissions (name) VALUES
    ('create_user'), ('delete_user'), ('manage_roles'),
    ('read_profile'), ('update_profile'), ('moderate_content');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin';

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name IN ('read_profile', 'update_profile', 'moderate_content')
WHERE r.name = 'moderator';

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r JOIN permissions p ON p.name IN ('read_profile', 'update_profile')
WHERE r.name = 'user';
