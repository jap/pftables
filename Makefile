_pftables.so: builder.py prebuilder.out
	python builder.py

prebuilder.out: prebuilder
	./prebuilder > $@

prebuilder: prebuilder.c

prebuilder.c: prebuilder.py
	python prebuilder.py

