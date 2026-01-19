.PHONY: all realtek realtek-% netforward netforward-% clean

ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

all:
	@echo "Specify platform target: realtek or netforward (e.g. 'make realtek', 'make netforward')."
	@echo "Use realtek-<goal>/netforward-<goal> to pass through goals such as test or cross-generic."

realtek:
	$(MAKE) -C build/realtek all

realtek-%:
	$(MAKE) -C build/realtek $(subst realtek-,,$@)

netforward:
	$(MAKE) -C build/netforward all

netforward-%:
	$(MAKE) -C build/netforward $(subst netforward-,,$@)

clean:
	$(MAKE) -C build/realtek clean
	$(MAKE) -C build/netforward clean
