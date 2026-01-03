
PR created on: Sat Jan  3 09:30:23 PM UTC 2026

# Assignment Summary

## Repository
https://github.com/faizi82/tatou2

## How to run unit tests in root repository 

python -m pytest -q


## HTML report and branch coverage 

python -m coverage erase
python -m coverage run --branch --source=server/src -m pytest -q
python -m coverage html


 ## PR Link 

 https://github.com/faizi82/tatou2/commit/81acf20b3b0d55334e5ce543ad8729f5775e2bcc 

 ## Notes 

A few branches in server.py remain partially covered because they depend on environment bootstrapping or CLI/script entry behavior (e.g., main, DB engine selection branches).
create-watermark and read-watermark routes are fully covered by the branch coverage tests.

 ##  List of new/added tests

test/test_create_watermark_branchcov.py
test/test_read_watermark_branchcov.py

## Other testing utilities added/updated

test/conftest.py (TEST_MODE SQLite + schema creation + DB cleanup for isolation)
test/mock_wm_methods.py (mock watermarking methods for deterministic behavi