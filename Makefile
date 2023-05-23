.PHONY: clean run

PWD := ${CURDIR}
NGINX_SRC_DIR = ~/Downloads/nginx
NGINX_INSTALL_DIR = $(PWD)/nginx

ngx_http_acme_module.so:
	cd $(NGINX_SRC_DIR) && \
	./configure --prefix=$(NGINX_INSTALL_DIR) --with-cc-opt="-I/opt/homebrew/opt/pcre2/include \
		-I/opt/homebrew/opt/openssl@1.1/include" --with-ld-opt="-L/opt/homebrew/opt/pcre2/lib \
		-L/opt/homebrew/opt/openssl@1.1/lib" \
		--with-compat --with-debug --with-http_addition_module --with-http_auth_request_module \
		--with-http_degradation_module  --with-http_gunzip_module --with-http_gzip_static_module \
		--with-http_random_index_module --with-http_realip_module --with-http_secure_link_module \
		--with-http_slice_module --with-http_ssl_module --with-http_stub_status_module \
		--with-http_sub_module --with-http_v2_module --with-pcre --with-pcre-jit --with-stream \
		--with-stream_ssl_module --with-stream_ssl_preread_module \
		--add-dynamic-module=$(PWD) && \
	make -j 4 install

run:
	cp $(PWD)/nginx.conf $(NGINX_INSTALL_DIR)/conf/nginx.conf
	$(NGINX_INSTALL_DIR)/sbin/nginx
clean:
	cd $(NGINX_SRC_DIR) && make clean || true
	rm -f ngx_http_acme_module.so