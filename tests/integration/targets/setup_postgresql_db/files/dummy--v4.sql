CREATE OR REPLACE FUNCTION dummy_display_ext_version()
RETURNS text LANGUAGE SQL AS 'SELECT (''v4'')::text';
