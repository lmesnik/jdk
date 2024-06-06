To find tests that ignore flags run:
make -- run-test JTREG_RETAIN=all TEST_VM_OPTS="-XX:+UseNewCode" TEST=:all