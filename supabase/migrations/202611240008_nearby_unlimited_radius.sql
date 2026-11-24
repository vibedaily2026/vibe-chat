-- ACHI Nearby Friends: remove the maximum search radius.
-- Location sharing remains opt-in; only approximate distance is returned.
-- Coordinates are never returned to clients.
CREATE OR REPLACE FUNCTION public.find_nearby_friends(
  p_radius_km double precision DEFAULT 50
)
RETURNS TABLE(user_id uuid, distance_km numeric)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $function$
DECLARE
  v_lat double precision;
  v_lon double precision;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'กรุณาเข้าสู่ระบบก่อน';
  END IF;

  SELECT latitude, longitude
  INTO v_lat, v_lon
  FROM private.nearby_locations
  WHERE private.nearby_locations.user_id = auth.uid()
    AND private.nearby_locations.is_sharing = true
    AND updated_at > now() - interval '30 minutes';

  IF v_lat IS NULL OR v_lon IS NULL THEN
    RETURN;
  END IF;

  RETURN QUERY
  SELECT
    other.user_id,
    ROUND((
      6371 * 2 * ASIN(SQRT(
        POWER(SIN(RADIANS(other.latitude - v_lat) / 2), 2)
        + COS(RADIANS(v_lat))
        * COS(RADIANS(other.latitude))
        * POWER(SIN(RADIANS(other.longitude - v_lon) / 2), 2)
      ))
    )::numeric, 1)
  FROM private.nearby_locations AS other
  WHERE other.user_id <> auth.uid()
    AND other.is_sharing = true
    AND other.updated_at > now() - interval '30 minutes'
    AND NOT EXISTS (
      SELECT 1
      FROM public.user_blocks b
      WHERE
        (b.blocker_id = auth.uid() AND b.blocked_id = other.user_id)
        OR
        (b.blocker_id = other.user_id AND b.blocked_id = auth.uid())
    );
END;
$function$;

REVOKE ALL ON FUNCTION public.find_nearby_friends(double precision) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.find_nearby_friends(double precision) TO authenticated;
