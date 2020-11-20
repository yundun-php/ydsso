# notice
#Make is very picky about spaces vs. tabs.
#Command lines absolutely must be indented with a single tab, and not spaces.
#You may need to adjust your editor to generate tab characters.

env:
	php -v
	php -i |grep php.ini

test:
	./vendor/bin/phpunit

deltag:
	git push --delete origin v0.2.38


.PHONY: env test deltag

