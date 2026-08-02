-- Seed dev SOC admin (password: demo123)
INSERT INTO users (organization_id, email, password_hash, role)
SELECT o.id, 'admin@demo.local', crypt('demo123', gen_salt('bf')), 'admin'::user_role
FROM organizations o WHERE o.slug = 'demo-org'
ON CONFLICT (organization_id, email) DO NOTHING;

INSERT INTO users (organization_id, email, password_hash, role)
SELECT o.id, 'analyst@demo.local', crypt('demo123', gen_salt('bf')), 'soc_analyst'::user_role
FROM organizations o WHERE o.slug = 'demo-org'
ON CONFLICT (organization_id, email) DO NOTHING;
