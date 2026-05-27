# Notes

## Why This Exists

Digital signage and dashboard projects often fail late because a customer URL refuses to load inside an iframe. RustCSPGuardian gives a quick local check before that failure reaches a device.

## Known Limits

- It checks response headers, not full browser runtime behavior.
- Some sites vary headers by region, user agent, redirect path, or authentication state.
- A URL marked unknown still needs manual verification in the target player.

## Maintenance Notes

- Keep examples safe and public.
- Do not include customer URLs in fixtures.
- Prefer adding a test case when a new header behavior is supported.
