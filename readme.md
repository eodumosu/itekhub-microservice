# Guideline how to read this document
Read this documentation with full concentration and understand clearly how the application working. I tried to describe 
as simple as possible. No need to run the application or understand the code initially. **Read the documentation and understand 
the workflow diagram first**. I have used Java, Spring Boot and Angular but you no need to know any specific language or technology to understand microservice 
concept. Just read the documentation first.   

Once you have completed the documentation then you can run every application in your local system by configuring system 
prerequisites and don't forget to notice terminal log when you run all application, it helps for better understanding. 
Here is total 5 separate application (1 frontend + 4 backend).
- microservice-ui (frontend)
- service-registry
- api-gateway
- product-service
- offer-service

# What is microservice?
Microservice is a modern as well as a popular architecture of designing software application over the last few years. 
There are lots of content on the internet to describe what microservice really is and those are very informative. 
But here I wanna describe it simply, concisely in production style.  

A microservice application is consist of different services where every service is an application which is
  1. **Independently deployable**   
  2. **Independently scalable**  

above two are the key requirements of a microservice application.

In this microservice application here are two service **product-service** and **offer-service** both independently 
deployable and scalable. **They are using two different database but this is not an issue about microservice architecture. 
They can use the same database.**

To expose these two service as microservice architecture I used two other service those are **service-registry** for 
service discovery and **api-gateway** for dynamic service routing as well as load balancing.

# Have a look the workflow
![workflow](readme-images/flow-diagram.png)

# Run the services

## System configuration prerequisites
### 1. Clone this project
Open terminal and run
````
git clone https://github.com/hnjaman/complete-microservice-application.git
````
In your current directory ``complete-microservice-application`` directory will be created with five different project inside.

### 2. Install Java and Maven
Install java 8 or higher version and Apache Maven 3.6.0 on your system.
Java 11 is installed in my system. This is not an issue. It will work fine in java 8 to java 11.

### 3. Install RabbitMQ 
### Download Erlang/OTP for Windows, from: https://www.erlang.org/downloads 
### Download RabbitMQ for Windows, from: https://github.com/rabbitmq/rabbitmq-server/releases/tag/v3.11.5 
### By default, Erlang downloads to: C:\Program Files\Erlang OTP 
### By default, RabbitMq downloads to: C:\Program Files\RabbitMQ Server 

Output folder: C:\Program Files\RabbitMQ Server
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5
Extract: INSTALL.txt
Extract: LICENSE-APACHE2-ExplorerCanvas.txt
Extract: LICENSE-APACHE2-excanvas.txt
Extract: LICENSE-APACHE2.txt
Extract: LICENSE-APL2-Stomp-Websocket.txt
Extract: LICENSE-BSD-base64js.txt
Extract: LICENSE-BSD-recon.txt
Extract: LICENSE-ISC-cowboy.txt
Extract: LICENSE-MIT-EJS.txt
Extract: LICENSE-MIT-EJS10.txt
Extract: LICENSE-MIT-Erlware-Commons.txt
Extract: LICENSE-MIT-Flot.txt
Extract: LICENSE-MIT-Mochi.txt
Extract: LICENSE-MIT-Sammy.txt
Extract: LICENSE-MIT-Sammy060.txt
Extract: LICENSE-MIT-jQuery.txt
Extract: LICENSE-MIT-jQuery164.txt
Extract: LICENSE-MPL-RabbitMQ.txt
Extract: LICENSE-MPL.txt
Extract: LICENSE-MPL2.txt
Extract: LICENSE-erlcloud.txt
Extract: LICENSE-httpc_aws.txt
Extract: LICENSE-rabbitmq_aws.txt
Extract: LICENSE.txt
Extract: readme-service.txt
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\escript
Extract: rabbitmq-diagnostics
Extract: rabbitmq-plugins
Extract: rabbitmq-queues
Extract: rabbitmq-streams
Extract: rabbitmq-tanzu
Extract: rabbitmq-upgrade
Extract: rabbitmqctl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\etc
Extract: README.txt
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\sbin
Extract: rabbitmq-defaults.bat
Extract: rabbitmq-diagnostics.bat
Extract: rabbitmq-echopid.bat
Extract: rabbitmq-env.bat
Extract: rabbitmq-plugins.bat
Extract: rabbitmq-queues.bat
Extract: rabbitmq-server.bat
Extract: rabbitmq-service.bat
Extract: rabbitmq-streams.bat
Extract: rabbitmq-tanzu.bat
Extract: rabbitmq-upgrade.bat
Extract: rabbitmqctl.bat
Output folder: C:\Program Files\RabbitMQ Server
Extract: rabbitmq.ico
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins
Extract: README.txt
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\accept-0.3.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\accept-0.3.5\ebin
Extract: accept.app
Extract: accept_encoding_header.beam
Extract: accept_header.beam
Extract: accept_neg.beam
Extract: accept_parser.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\accept-0.3.5\include
Extract: accept.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\amqp10_client-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\amqp10_client-3.11.5\ebin
Extract: amqp10_client.app
Extract: amqp10_client.beam
Extract: amqp10_client_app.beam
Extract: amqp10_client_connection.beam
Extract: amqp10_client_connection_sup.beam
Extract: amqp10_client_connections_sup.beam
Extract: amqp10_client_frame_reader.beam
Extract: amqp10_client_session.beam
Extract: amqp10_client_sessions_sup.beam
Extract: amqp10_client_sup.beam
Extract: amqp10_client_types.beam
Extract: amqp10_msg.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\amqp10_common-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\amqp10_common-3.11.5\ebin
Extract: amqp10_binary_generator.beam
Extract: amqp10_binary_parser.beam
Extract: amqp10_common.app
Extract: amqp10_framing.beam
Extract: amqp10_framing0.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\amqp10_common-3.11.5\include
Extract: amqp10_framing.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\amqp_client-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\amqp_client-3.11.5\ebin
Extract: amqp_auth_mechanisms.beam
Extract: amqp_channel.beam
Extract: amqp_channel_sup.beam
Extract: amqp_channel_sup_sup.beam
Extract: amqp_channels_manager.beam
Extract: amqp_client.app
Extract: amqp_client.beam
Extract: amqp_connection.beam
Extract: amqp_connection_sup.beam
Extract: amqp_connection_type_sup.beam
Extract: amqp_direct_connection.beam
Extract: amqp_direct_consumer.beam
Extract: amqp_gen_connection.beam
Extract: amqp_gen_consumer.beam
Extract: amqp_main_reader.beam
Extract: amqp_network_connection.beam
Extract: amqp_rpc_client.beam
Extract: amqp_rpc_server.beam
Extract: amqp_selective_consumer.beam
Extract: amqp_ssl.beam
Extract: amqp_sup.beam
Extract: amqp_uri.beam
Extract: amqp_util.beam
Extract: rabbit_routing_util.beam
Extract: uri_parser.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\amqp_client-3.11.5\include
Extract: amqp_client.hrl
Extract: amqp_client_internal.hrl
Extract: amqp_gen_consumer_spec.hrl
Extract: rabbit_routing_prefixes.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\aten-0.5.8
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\aten-0.5.8\ebin
Extract: aten.app
Extract: aten.beam
Extract: aten_app.beam
Extract: aten_detect.beam
Extract: aten_detector.beam
Extract: aten_emitter.beam
Extract: aten_sink.beam
Extract: aten_sup.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\base64url-1.0.1
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\base64url-1.0.1\ebin
Extract: base64url.app
Extract: base64url.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\cowboy-2.8.0
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\cowboy-2.8.0\ebin
Extract: cowboy.app
Extract: cowboy.beam
Extract: cowboy_app.beam
Extract: cowboy_bstr.beam
Extract: cowboy_children.beam
Extract: cowboy_clear.beam
Extract: cowboy_clock.beam
Extract: cowboy_compress_h.beam
Extract: cowboy_constraints.beam
Extract: cowboy_handler.beam
Extract: cowboy_http.beam
Extract: cowboy_http2.beam
Extract: cowboy_loop.beam
Extract: cowboy_metrics_h.beam
Extract: cowboy_middleware.beam
Extract: cowboy_req.beam
Extract: cowboy_rest.beam
Extract: cowboy_router.beam
Extract: cowboy_static.beam
Extract: cowboy_stream.beam
Extract: cowboy_stream_h.beam
Extract: cowboy_sub_protocol.beam
Extract: cowboy_sup.beam
Extract: cowboy_tls.beam
Extract: cowboy_tracer_h.beam
Extract: cowboy_websocket.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\cowlib-2.9.1
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\cowlib-2.9.1\ebin
Extract: cow_base64url.beam
Extract: cow_cookie.beam
Extract: cow_date.beam
Extract: cow_hpack.beam
Extract: cow_http.beam
Extract: cow_http2.beam
Extract: cow_http2_machine.beam
Extract: cow_http_hd.beam
Extract: cow_http_struct_hd.beam
Extract: cow_http_te.beam
Extract: cow_iolists.beam
Extract: cow_link.beam
Extract: cow_mimetypes.beam
Extract: cow_multipart.beam
Extract: cow_qs.beam
Extract: cow_spdy.beam
Extract: cow_sse.beam
Extract: cow_uri.beam
Extract: cow_uri_template.beam
Extract: cow_ws.beam
Extract: cowlib.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\cowlib-2.9.1\include
Extract: cow_inline.hrl
Extract: cow_parse.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\credentials_obfuscation-3.2.0
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\credentials_obfuscation-3.2.0\ebin
Extract: credentials_obfuscation.app
Extract: credentials_obfuscation.beam
Extract: credentials_obfuscation_app.beam
Extract: credentials_obfuscation_pbe.beam
Extract: credentials_obfuscation_sup.beam
Extract: credentials_obfuscation_svc.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\credentials_obfuscation-3.2.0\include
Extract: credentials_obfuscation.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\cuttlefish-3.1.0
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\cuttlefish-3.1.0\ebin
Extract: conf_parse.beam
Extract: cuttlefish.app
Extract: cuttlefish.beam
Extract: cuttlefish_advanced.beam
Extract: cuttlefish_bytesize.beam
Extract: cuttlefish_conf.beam
Extract: cuttlefish_datatypes.beam
Extract: cuttlefish_duration.beam
Extract: cuttlefish_duration_parse.beam
Extract: cuttlefish_effective.beam
Extract: cuttlefish_enum.beam
Extract: cuttlefish_error.beam
Extract: cuttlefish_escript.beam
Extract: cuttlefish_flag.beam
Extract: cuttlefish_generator.beam
Extract: cuttlefish_mapping.beam
Extract: cuttlefish_rebar_plugin.beam
Extract: cuttlefish_schema.beam
Extract: cuttlefish_translation.beam
Extract: cuttlefish_unit.beam
Extract: cuttlefish_util.beam
Extract: cuttlefish_validator.beam
Extract: cuttlefish_variable.beam
Extract: cuttlefish_vmargs.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\cuttlefish-3.1.0\priv
Extract: erlang_vm.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\eetcd-0.3.6
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\eetcd-0.3.6\ebin
Extract: auth_pb.beam
Extract: eetcd.app
Extract: eetcd.beam
Extract: eetcd_app.beam
Extract: eetcd_auth.beam
Extract: eetcd_auth_gen.beam
Extract: eetcd_cluster.beam
Extract: eetcd_cluster_gen.beam
Extract: eetcd_compare.beam
Extract: eetcd_conn.beam
Extract: eetcd_conn_sup.beam
Extract: eetcd_data_coercion.beam
Extract: eetcd_election.beam
Extract: eetcd_election_gen.beam
Extract: eetcd_grpc.beam
Extract: eetcd_health_gen.beam
Extract: eetcd_kv.beam
Extract: eetcd_kv_gen.beam
Extract: eetcd_lease.beam
Extract: eetcd_lease_gen.beam
Extract: eetcd_lease_sup.beam
Extract: eetcd_lock.beam
Extract: eetcd_lock_gen.beam
Extract: eetcd_maintenance.beam
Extract: eetcd_maintenance_gen.beam
Extract: eetcd_op.beam
Extract: eetcd_stream.beam
Extract: eetcd_sup.beam
Extract: eetcd_watch.beam
Extract: eetcd_watch_gen.beam
Extract: gogo_pb.beam
Extract: health_pb.beam
Extract: kv_pb.beam
Extract: router_pb.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\eetcd-0.3.6\include
Extract: eetcd.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\eetcd-0.3.6\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\eetcd-0.3.6\priv\protos
Extract: auth.proto
Extract: gogo.proto
Extract: kv.proto
Extract: router.proto
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\enough-0.1.0
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\enough-0.1.0\ebin
Extract: enough.app
Extract: enough.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\gen_batch_server-0.8.8
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\gen_batch_server-0.8.8\ebin
Extract: gen_batch_server.app
Extract: gen_batch_server.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\getopt-1.0.2
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\getopt-1.0.2\ebin
Extract: getopt.app
Extract: getopt.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\gun-1.3.3
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\gun-1.3.3\ebin
Extract: gun.app
Extract: gun.beam
Extract: gun_app.beam
Extract: gun_content_handler.beam
Extract: gun_data_h.beam
Extract: gun_http.beam
Extract: gun_http2.beam
Extract: gun_sse_h.beam
Extract: gun_sup.beam
Extract: gun_tcp.beam
Extract: gun_tls.beam
Extract: gun_ws.beam
Extract: gun_ws_h.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\jose-1.11.3
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\jose-1.11.3\ebin
Extract: jose.app
Extract: jose.beam
Extract: jose_app.beam
Extract: jose_base.beam
Extract: jose_base64.beam
Extract: jose_base64url.beam
Extract: jose_block_encryptor.beam
Extract: jose_chacha20_poly1305.beam
Extract: jose_chacha20_poly1305_crypto.beam
Extract: jose_chacha20_poly1305_libsodium.beam
Extract: jose_chacha20_poly1305_unsupported.beam
Extract: jose_crypto_compat.beam
Extract: jose_curve25519.beam
Extract: jose_curve25519_libdecaf.beam
Extract: jose_curve25519_libsodium.beam
Extract: jose_curve25519_unsupported.beam
Extract: jose_curve448.beam
Extract: jose_curve448_libdecaf.beam
Extract: jose_curve448_unsupported.beam
Extract: jose_json.beam
Extract: jose_json_jason.beam
Extract: jose_json_jiffy.beam
Extract: jose_json_jsone.beam
Extract: jose_json_jsx.beam
Extract: jose_json_ojson.beam
Extract: jose_json_poison.beam
Extract: jose_json_poison_compat_encoder.beam
Extract: jose_json_poison_lexical_encoder.beam
Extract: jose_json_thoas.beam
Extract: jose_json_unsupported.beam
Extract: jose_jwa.beam
Extract: jose_jwa_aes.beam
Extract: jose_jwa_aes_kw.beam
Extract: jose_jwa_base64url.beam
Extract: jose_jwa_bench.beam
Extract: jose_jwa_chacha20.beam
Extract: jose_jwa_chacha20_poly1305.beam
Extract: jose_jwa_concat_kdf.beam
Extract: jose_jwa_curve25519.beam
Extract: jose_jwa_curve448.beam
Extract: jose_jwa_ed25519.beam
Extract: jose_jwa_ed448.beam
Extract: jose_jwa_hchacha20.beam
Extract: jose_jwa_math.beam
Extract: jose_jwa_pkcs1.beam
Extract: jose_jwa_pkcs5.beam
Extract: jose_jwa_pkcs7.beam
Extract: jose_jwa_poly1305.beam
Extract: jose_jwa_sha3.beam
Extract: jose_jwa_unsupported.beam
Extract: jose_jwa_x25519.beam
Extract: jose_jwa_x448.beam
Extract: jose_jwa_xchacha20.beam
Extract: jose_jwa_xchacha20_poly1305.beam
Extract: jose_jwe.beam
Extract: jose_jwe_alg.beam
Extract: jose_jwe_alg_aes_kw.beam
Extract: jose_jwe_alg_c20p_kw.beam
Extract: jose_jwe_alg_dir.beam
Extract: jose_jwe_alg_ecdh_1pu.beam
Extract: jose_jwe_alg_ecdh_es.beam
Extract: jose_jwe_alg_pbes2.beam
Extract: jose_jwe_alg_rsa.beam
Extract: jose_jwe_alg_xc20p_kw.beam
Extract: jose_jwe_enc.beam
Extract: jose_jwe_enc_aes.beam
Extract: jose_jwe_enc_c20p.beam
Extract: jose_jwe_enc_xc20p.beam
Extract: jose_jwe_zip.beam
Extract: jose_jwk.beam
Extract: jose_jwk_der.beam
Extract: jose_jwk_kty.beam
Extract: jose_jwk_kty_ec.beam
Extract: jose_jwk_kty_oct.beam
Extract: jose_jwk_kty_okp_ed25519.beam
Extract: jose_jwk_kty_okp_ed25519ph.beam
Extract: jose_jwk_kty_okp_ed448.beam
Extract: jose_jwk_kty_okp_ed448ph.beam
Extract: jose_jwk_kty_okp_x25519.beam
Extract: jose_jwk_kty_okp_x448.beam
Extract: jose_jwk_kty_rsa.beam
Extract: jose_jwk_oct.beam
Extract: jose_jwk_openssh_key.beam
Extract: jose_jwk_pem.beam
Extract: jose_jwk_set.beam
Extract: jose_jwk_use_enc.beam
Extract: jose_jwk_use_sig.beam
Extract: jose_jws.beam
Extract: jose_jws_alg.beam
Extract: jose_jws_alg_ecdsa.beam
Extract: jose_jws_alg_eddsa.beam
Extract: jose_jws_alg_hmac.beam
Extract: jose_jws_alg_none.beam
Extract: jose_jws_alg_poly1305.beam
Extract: jose_jws_alg_rsa_pkcs1_v1_5.beam
Extract: jose_jws_alg_rsa_pss.beam
Extract: jose_jwt.beam
Extract: jose_public_key.beam
Extract: jose_server.beam
Extract: jose_sha3.beam
Extract: jose_sha3_keccakf1600_driver.beam
Extract: jose_sha3_keccakf1600_nif.beam
Extract: jose_sha3_libdecaf.beam
Extract: jose_sha3_unsupported.beam
Extract: jose_sup.beam
Extract: jose_xchacha20_poly1305.beam
Extract: jose_xchacha20_poly1305_crypto.beam
Extract: jose_xchacha20_poly1305_unsupported.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\jose-1.11.3\include
Extract: jose.hrl
Extract: jose_base.hrl
Extract: jose_compat.hrl
Extract: jose_jwe.hrl
Extract: jose_jwk.hrl
Extract: jose_jws.hrl
Extract: jose_jwt.hrl
Extract: jose_public_key.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\jose-1.11.3\priv
Extract: Dockerfile
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\observer_cli-1.7.3
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\observer_cli-1.7.3\ebin
Extract: observer_cli.app
Extract: observer_cli.beam
Extract: observer_cli_application.beam
Extract: observer_cli_escriptize.beam
Extract: observer_cli_ets.beam
Extract: observer_cli_help.beam
Extract: observer_cli_inet.beam
Extract: observer_cli_lib.beam
Extract: observer_cli_mnesia.beam
Extract: observer_cli_plugin.beam
Extract: observer_cli_port.beam
Extract: observer_cli_process.beam
Extract: observer_cli_store.beam
Extract: observer_cli_system.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\observer_cli-1.7.3\include
Extract: observer_cli.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\osiris-1.3.3
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\osiris-1.3.3\ebin
Extract: osiris.app
Extract: osiris.beam
Extract: osiris_app.beam
Extract: osiris_bench.beam
Extract: osiris_counters.beam
Extract: osiris_log.beam
Extract: osiris_log_shared.beam
Extract: osiris_replica.beam
Extract: osiris_replica_reader.beam
Extract: osiris_replica_reader_sup.beam
Extract: osiris_retention.beam
Extract: osiris_server_sup.beam
Extract: osiris_sup.beam
Extract: osiris_tracking.beam
Extract: osiris_util.beam
Extract: osiris_writer.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\prometheus-4.9.1
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\prometheus-4.9.1\ebin
Extract: prometheus.app
Extract: prometheus.beam
Extract: prometheus_boolean.beam
Extract: prometheus_buckets.beam
Extract: prometheus_collector.beam
Extract: prometheus_counter.beam
Extract: prometheus_format.beam
Extract: prometheus_gauge.beam
Extract: prometheus_histogram.beam
Extract: prometheus_http.beam
Extract: prometheus_instrumenter.beam
Extract: prometheus_metric.beam
Extract: prometheus_metric_spec.beam
Extract: prometheus_misc.beam
Extract: prometheus_mnesia.beam
Extract: prometheus_mnesia_collector.beam
Extract: prometheus_model.beam
Extract: prometheus_model_helpers.beam
Extract: prometheus_protobuf_format.beam
Extract: prometheus_quantile_summary.beam
Extract: prometheus_registry.beam
Extract: prometheus_summary.beam
Extract: prometheus_sup.beam
Extract: prometheus_test_instrumenter.beam
Extract: prometheus_text_format.beam
Extract: prometheus_time.beam
Extract: prometheus_vm_dist_collector.beam
Extract: prometheus_vm_memory_collector.beam
Extract: prometheus_vm_msacc_collector.beam
Extract: prometheus_vm_statistics_collector.beam
Extract: prometheus_vm_system_info_collector.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\prometheus-4.9.1\include
Extract: prometheus.hrl
Extract: prometheus_model.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\quantile_estimator-0.2.1
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\quantile_estimator-0.2.1\ebin
Extract: quantile.beam
Extract: quantile_estimator.app
Extract: quantile_estimator.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\quantile_estimator-0.2.1\include
Extract: quantile_estimator.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\ra-2.4.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\ra-2.4.5\ebin
Extract: ra.app
Extract: ra.beam
Extract: ra_app.beam
Extract: ra_bench.beam
Extract: ra_counters.beam
Extract: ra_dbg.beam
Extract: ra_directory.beam
Extract: ra_env.beam
Extract: ra_file_handle.beam
Extract: ra_flru.beam
Extract: ra_leaderboard.beam
Extract: ra_lib.beam
Extract: ra_log.beam
Extract: ra_log_ets.beam
Extract: ra_log_meta.beam
Extract: ra_log_pre_init.beam
Extract: ra_log_reader.beam
Extract: ra_log_segment.beam
Extract: ra_log_segment_writer.beam
Extract: ra_log_snapshot.beam
Extract: ra_log_sup.beam
Extract: ra_log_wal.beam
Extract: ra_log_wal_sup.beam
Extract: ra_machine.beam
Extract: ra_machine_ets.beam
Extract: ra_machine_simple.beam
Extract: ra_metrics_ets.beam
Extract: ra_monitors.beam
Extract: ra_server.beam
Extract: ra_server_proc.beam
Extract: ra_server_sup.beam
Extract: ra_server_sup_sup.beam
Extract: ra_snapshot.beam
Extract: ra_sup.beam
Extract: ra_system.beam
Extract: ra_system_sup.beam
Extract: ra_systems_sup.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbit-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbit-3.11.5\ebin
Extract: amqqueue.beam
Extract: background_gc.beam
Extract: code_server_cache.beam
Extract: gatherer.beam
Extract: gm.beam
Extract: internal_user.beam
Extract: lqueue.beam
Extract: mirrored_supervisor.beam
Extract: mirrored_supervisor_sups.beam
Extract: pg_local.beam
Extract: pid_recomposition.beam
Extract: rabbit.app
Extract: rabbit.beam
Extract: rabbit_access_control.beam
Extract: rabbit_alarm.beam
Extract: rabbit_amqqueue.beam
Extract: rabbit_amqqueue_process.beam
Extract: rabbit_amqqueue_sup.beam
Extract: rabbit_amqqueue_sup_sup.beam
Extract: rabbit_auth_backend_internal.beam
Extract: rabbit_auth_mechanism_amqplain.beam
Extract: rabbit_auth_mechanism_cr_demo.beam
Extract: rabbit_auth_mechanism_plain.beam
Extract: rabbit_autoheal.beam
Extract: rabbit_backing_queue.beam
Extract: rabbit_basic.beam
Extract: rabbit_binding.beam
Extract: rabbit_boot_steps.beam
Extract: rabbit_channel.beam
Extract: rabbit_channel_interceptor.beam
Extract: rabbit_channel_sup.beam
Extract: rabbit_channel_sup_sup.beam
Extract: rabbit_channel_tracking.beam
Extract: rabbit_channel_tracking_handler.beam
Extract: rabbit_classic_queue.beam
Extract: rabbit_classic_queue_index_v2.beam
Extract: rabbit_classic_queue_store_v2.beam
Extract: rabbit_client_sup.beam
Extract: rabbit_config.beam
Extract: rabbit_confirms.beam
Extract: rabbit_connection_helper_sup.beam
Extract: rabbit_connection_sup.beam
Extract: rabbit_connection_tracking.beam
Extract: rabbit_connection_tracking_handler.beam
Extract: rabbit_control_pbe.beam
Extract: rabbit_core_ff.beam
Extract: rabbit_core_metrics_gc.beam
Extract: rabbit_credential_validation.beam
Extract: rabbit_credential_validator.beam
Extract: rabbit_credential_validator_accept_everything.beam
Extract: rabbit_credential_validator_min_password_length.beam
Extract: rabbit_credential_validator_password_regexp.beam
Extract: rabbit_dead_letter.beam
Extract: rabbit_definitions.beam
Extract: rabbit_definitions_hashing.beam
Extract: rabbit_definitions_import_https.beam
Extract: rabbit_definitions_import_local_filesystem.beam
Extract: rabbit_diagnostics.beam
Extract: rabbit_direct.beam
Extract: rabbit_direct_reply_to.beam
Extract: rabbit_disk_monitor.beam
Extract: rabbit_epmd_monitor.beam
Extract: rabbit_event_consumer.beam
Extract: rabbit_exchange.beam
Extract: rabbit_exchange_decorator.beam
Extract: rabbit_exchange_parameters.beam
Extract: rabbit_exchange_type_direct.beam
Extract: rabbit_exchange_type_fanout.beam
Extract: rabbit_exchange_type_headers.beam
Extract: rabbit_exchange_type_invalid.beam
Extract: rabbit_exchange_type_topic.beam
Extract: rabbit_feature_flags.beam
Extract: rabbit_ff_controller.beam
Extract: rabbit_ff_extra.beam
Extract: rabbit_ff_registry.beam
Extract: rabbit_ff_registry_factory.beam
Extract: rabbit_fhc_helpers.beam
Extract: rabbit_fifo.beam
Extract: rabbit_fifo_client.beam
Extract: rabbit_fifo_dlx.beam
Extract: rabbit_fifo_dlx_client.beam
Extract: rabbit_fifo_dlx_sup.beam
Extract: rabbit_fifo_dlx_worker.beam
Extract: rabbit_fifo_index.beam
Extract: rabbit_fifo_v0.beam
Extract: rabbit_fifo_v1.beam
Extract: rabbit_file.beam
Extract: rabbit_framing.beam
Extract: rabbit_global_counters.beam
Extract: rabbit_guid.beam
Extract: rabbit_health_check.beam
Extract: rabbit_limiter.beam
Extract: rabbit_log_channel.beam
Extract: rabbit_log_connection.beam
Extract: rabbit_log_feature_flags.beam
Extract: rabbit_log_mirroring.beam
Extract: rabbit_log_prelaunch.beam
Extract: rabbit_log_queue.beam
Extract: rabbit_log_tail.beam
Extract: rabbit_log_upgrade.beam
Extract: rabbit_logger_exchange_h.beam
Extract: rabbit_looking_glass.beam
Extract: rabbit_maintenance.beam
Extract: rabbit_memory_monitor.beam
Extract: rabbit_metrics.beam
Extract: rabbit_mirror_queue_coordinator.beam
Extract: rabbit_mirror_queue_master.beam
Extract: rabbit_mirror_queue_misc.beam
Extract: rabbit_mirror_queue_mode.beam
Extract: rabbit_mirror_queue_mode_all.beam
Extract: rabbit_mirror_queue_mode_exactly.beam
Extract: rabbit_mirror_queue_mode_nodes.beam
Extract: rabbit_mirror_queue_slave.beam
Extract: rabbit_mirror_queue_sync.beam
Extract: rabbit_mnesia.beam
Extract: rabbit_mnesia_rename.beam
Extract: rabbit_msg_file.beam
Extract: rabbit_msg_record.beam
Extract: rabbit_msg_store.beam
Extract: rabbit_msg_store_ets_index.beam
Extract: rabbit_msg_store_gc.beam
Extract: rabbit_networking.beam
Extract: rabbit_networking_store.beam
Extract: rabbit_node_monitor.beam
Extract: rabbit_nodes.beam
Extract: rabbit_observer_cli.beam
Extract: rabbit_observer_cli_classic_queues.beam
Extract: rabbit_osiris_metrics.beam
Extract: rabbit_parameter_validation.beam
Extract: rabbit_password.beam
Extract: rabbit_password_hashing_md5.beam
Extract: rabbit_password_hashing_sha256.beam
Extract: rabbit_password_hashing_sha512.beam
Extract: rabbit_peer_discovery.beam
Extract: rabbit_peer_discovery_classic_config.beam
Extract: rabbit_peer_discovery_dns.beam
Extract: rabbit_plugins.beam
Extract: rabbit_policies.beam
Extract: rabbit_policy.beam
Extract: rabbit_policy_merge_strategy.beam
Extract: rabbit_prelaunch_cluster.beam
Extract: rabbit_prelaunch_enabled_plugins_file.beam
Extract: rabbit_prelaunch_feature_flags.beam
Extract: rabbit_prelaunch_logging.beam
Extract: rabbit_prequeue.beam
Extract: rabbit_priority_queue.beam
Extract: rabbit_queue_consumers.beam
Extract: rabbit_queue_decorator.beam
Extract: rabbit_queue_index.beam
Extract: rabbit_queue_location.beam
Extract: rabbit_queue_location_client_local.beam
Extract: rabbit_queue_location_min_masters.beam
Extract: rabbit_queue_location_random.beam
Extract: rabbit_queue_location_validator.beam
Extract: rabbit_queue_master_location_misc.beam
Extract: rabbit_queue_master_locator.beam
Extract: rabbit_queue_type.beam
Extract: rabbit_queue_type_util.beam
Extract: rabbit_quorum_memory_manager.beam
Extract: rabbit_quorum_queue.beam
Extract: rabbit_ra_registry.beam
Extract: rabbit_ra_systems.beam
Extract: rabbit_reader.beam
Extract: rabbit_recovery_terms.beam
Extract: rabbit_release_series.beam
Extract: rabbit_restartable_sup.beam
Extract: rabbit_router.beam
Extract: rabbit_runtime_parameters.beam
Extract: rabbit_ssl.beam
Extract: rabbit_stream_coordinator.beam
Extract: rabbit_stream_queue.beam
Extract: rabbit_stream_sac_coordinator.beam
Extract: rabbit_sup.beam
Extract: rabbit_sysmon_handler.beam
Extract: rabbit_sysmon_minder.beam
Extract: rabbit_table.beam
Extract: rabbit_trace.beam
Extract: rabbit_tracking.beam
Extract: rabbit_tracking_store.beam
Extract: rabbit_upgrade.beam
Extract: rabbit_upgrade_functions.beam
Extract: rabbit_upgrade_preparation.beam
Extract: rabbit_variable_queue.beam
Extract: rabbit_version.beam
Extract: rabbit_vhost.beam
Extract: rabbit_vhost_limit.beam
Extract: rabbit_vhost_msg_store.beam
Extract: rabbit_vhost_process.beam
Extract: rabbit_vhost_sup.beam
Extract: rabbit_vhost_sup_sup.beam
Extract: rabbit_vhost_sup_wrapper.beam
Extract: rabbit_vm.beam
Extract: supervised_lifecycle.beam
Extract: tcp_listener.beam
Extract: tcp_listener_sup.beam
Extract: term_to_binary_compat.beam
Extract: vhost.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbit-3.11.5\include
Extract: amqqueue.hrl
Extract: amqqueue_v2.hrl
Extract: gm_specs.hrl
Extract: rabbit_global_counters.hrl
Extract: vhost.hrl
Extract: vhost_v2.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbit-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbit-3.11.5\priv\schema
Extract: rabbit.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbit_common-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbit_common-3.11.5\ebin
Extract: app_utils.beam
Extract: code_version.beam
Extract: credit_flow.beam
Extract: delegate.beam
Extract: delegate_sup.beam
Extract: file_handle_cache.beam
Extract: file_handle_cache_stats.beam
Extract: gen_server2.beam
Extract: mirrored_supervisor_locks.beam
Extract: mnesia_sync.beam
Extract: pmon.beam
Extract: priority_queue.beam
Extract: rabbit_amqp_connection.beam
Extract: rabbit_amqqueue_common.beam
Extract: rabbit_auth_backend_dummy.beam
Extract: rabbit_auth_mechanism.beam
Extract: rabbit_authn_backend.beam
Extract: rabbit_authz_backend.beam
Extract: rabbit_basic_common.beam
Extract: rabbit_binary_generator.beam
Extract: rabbit_binary_parser.beam
Extract: rabbit_cert_info.beam
Extract: rabbit_channel_common.beam
Extract: rabbit_command_assembler.beam
Extract: rabbit_common.app
Extract: rabbit_control_misc.beam
Extract: rabbit_core_metrics.beam
Extract: rabbit_data_coercion.beam
Extract: rabbit_date_time.beam
Extract: rabbit_env.beam
Extract: rabbit_error_logger_handler.beam
Extract: rabbit_event.beam
Extract: rabbit_exchange_type.beam
Extract: rabbit_framing_amqp_0_8.beam
Extract: rabbit_framing_amqp_0_9_1.beam
Extract: rabbit_heartbeat.beam
Extract: rabbit_http_util.beam
Extract: rabbit_json.beam
Extract: rabbit_log.beam
Extract: rabbit_misc.beam
Extract: rabbit_msg_store_index.beam
Extract: rabbit_net.beam
Extract: rabbit_nodes_common.beam
Extract: rabbit_numerical.beam
Extract: rabbit_password_hashing.beam
Extract: rabbit_pbe.beam
Extract: rabbit_peer_discovery_backend.beam
Extract: rabbit_policy_validator.beam
Extract: rabbit_queue_collector.beam
Extract: rabbit_registry.beam
Extract: rabbit_registry_class.beam
Extract: rabbit_resource_monitor_misc.beam
Extract: rabbit_runtime.beam
Extract: rabbit_runtime_parameter.beam
Extract: rabbit_semver.beam
Extract: rabbit_semver_parser.beam
Extract: rabbit_ssl_options.beam
Extract: rabbit_types.beam
Extract: rabbit_writer.beam
Extract: supervisor2.beam
Extract: vm_memory_monitor.beam
Extract: worker_pool.beam
Extract: worker_pool_sup.beam
Extract: worker_pool_worker.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbit_common-3.11.5\include
Extract: logging.hrl
Extract: rabbit.hrl
Extract: rabbit_core_metrics.hrl
Extract: rabbit_framing.hrl
Extract: rabbit_memory.hrl
Extract: rabbit_misc.hrl
Extract: rabbit_msg_store.hrl
Extract: resource.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_amqp1_0-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_amqp1_0-3.11.5\ebin
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.ListAmqp10ConnectionsCommand.beam
Extract: rabbit_amqp1_0.beam
Extract: rabbit_amqp1_0_channel.beam
Extract: rabbit_amqp1_0_incoming_link.beam
Extract: rabbit_amqp1_0_link_util.beam
Extract: rabbit_amqp1_0_message.beam
Extract: rabbit_amqp1_0_outgoing_link.beam
Extract: rabbit_amqp1_0_reader.beam
Extract: rabbit_amqp1_0_session.beam
Extract: rabbit_amqp1_0_session_process.beam
Extract: rabbit_amqp1_0_session_sup.beam
Extract: rabbit_amqp1_0_session_sup_sup.beam
Extract: rabbit_amqp1_0_util.beam
Extract: rabbit_amqp1_0_writer.beam
Extract: rabbitmq_amqp1_0.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_amqp1_0-3.11.5\include
Extract: rabbit_amqp1_0.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_amqp1_0-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_amqp1_0-3.11.5\priv\schema
Extract: rabbitmq_amqp1_0.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_cache-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_cache-3.11.5\ebin
Extract: rabbit_auth_backend_cache.beam
Extract: rabbit_auth_backend_cache_app.beam
Extract: rabbit_auth_cache.beam
Extract: rabbit_auth_cache_dict.beam
Extract: rabbit_auth_cache_ets.beam
Extract: rabbit_auth_cache_ets_segmented.beam
Extract: rabbit_auth_cache_ets_segmented_stateless.beam
Extract: rabbitmq_auth_backend_cache.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_cache-3.11.5\include
Extract: rabbit_auth_backend_cache.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_cache-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_cache-3.11.5\priv\schema
Extract: rabbitmq_auth_backend_cache.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_http-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_http-3.11.5\ebin
Extract: rabbit_auth_backend_http.beam
Extract: rabbit_auth_backend_http_app.beam
Extract: rabbitmq_auth_backend_http.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_http-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_http-3.11.5\priv\schema
Extract: rabbitmq_auth_backend_http.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_ldap-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_ldap-3.11.5\ebin
Extract: rabbit_auth_backend_ldap.beam
Extract: rabbit_auth_backend_ldap_app.beam
Extract: rabbit_auth_backend_ldap_util.beam
Extract: rabbit_log_ldap.beam
Extract: rabbitmq_auth_backend_ldap.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_ldap-3.11.5\include
Extract: logging.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_ldap-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_ldap-3.11.5\priv\schema
Extract: rabbitmq_auth_backend_ldap.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_oauth2-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_oauth2-3.11.5\ebin
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.AddUaaKeyCommand.beam
Extract: rabbit_auth_backend_oauth2.beam
Extract: rabbit_auth_backend_oauth2_app.beam
Extract: rabbit_oauth2_scope.beam
Extract: rabbitmq_auth_backend_oauth2.app
Extract: uaa_jwks.beam
Extract: uaa_jwt.beam
Extract: uaa_jwt_jwk.beam
Extract: uaa_jwt_jwt.beam
Extract: wildcard.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_oauth2-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_backend_oauth2-3.11.5\priv\schema
Extract: rabbitmq_auth_backend_oauth2.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_mechanism_ssl-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_auth_mechanism_ssl-3.11.5\ebin
Extract: rabbit_auth_mechanism_ssl.beam
Extract: rabbit_auth_mechanism_ssl_app.beam
Extract: rabbitmq_auth_mechanism_ssl.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_aws-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_aws-3.11.5\ebin
Extract: rabbitmq_aws.app
Extract: rabbitmq_aws.beam
Extract: rabbitmq_aws_app.beam
Extract: rabbitmq_aws_config.beam
Extract: rabbitmq_aws_json.beam
Extract: rabbitmq_aws_sign.beam
Extract: rabbitmq_aws_sup.beam
Extract: rabbitmq_aws_urilib.beam
Extract: rabbitmq_aws_xml.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_aws-3.11.5\include
Extract: rabbitmq_aws.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_aws-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_aws-3.11.5\priv\schema
Extract: rabbitmq_aws.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_consistent_hash_exchange-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_consistent_hash_exchange-3.11.5\ebin
Extract: Elixir.RabbitMQ.CLI.Diagnostics.Commands.ConsistentHashExchangeRingStateCommand.beam
Extract: rabbit_exchange_type_consistent_hash.beam
Extract: rabbitmq_consistent_hash_exchange.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_consistent_hash_exchange-3.11.5\include
Extract: rabbitmq_consistent_hash_exchange.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_event_exchange-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_event_exchange-3.11.5\ebin
Extract: rabbit_event_exchange_decorator.beam
Extract: rabbit_exchange_type_event.beam
Extract: rabbitmq_event_exchange.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_event_exchange-3.11.5\include
Extract: rabbit_event_exchange.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_event_exchange-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_event_exchange-3.11.5\priv\schema
Extract: rabbitmq_event_exchange.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_federation-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_federation-3.11.5\ebin
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.FederationStatusCommand.beam
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.RestartFederationLinkCommand.beam
Extract: rabbit_federation_app.beam
Extract: rabbit_federation_db.beam
Extract: rabbit_federation_event.beam
Extract: rabbit_federation_exchange.beam
Extract: rabbit_federation_exchange_link.beam
Extract: rabbit_federation_exchange_link_sup_sup.beam
Extract: rabbit_federation_link_sup.beam
Extract: rabbit_federation_link_util.beam
Extract: rabbit_federation_parameters.beam
Extract: rabbit_federation_pg.beam
Extract: rabbit_federation_queue.beam
Extract: rabbit_federation_queue_link.beam
Extract: rabbit_federation_queue_link_sup_sup.beam
Extract: rabbit_federation_status.beam
Extract: rabbit_federation_sup.beam
Extract: rabbit_federation_upstream.beam
Extract: rabbit_federation_upstream_exchange.beam
Extract: rabbit_federation_util.beam
Extract: rabbit_log_federation.beam
Extract: rabbitmq_federation.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_federation-3.11.5\include
Extract: logging.hrl
Extract: rabbit_federation.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_federation_management-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_federation_management-3.11.5\ebin
Extract: rabbit_federation_mgmt.beam
Extract: rabbitmq_federation_management.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_federation_management-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_federation_management-3.11.5\priv\www
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_federation_management-3.11.5\priv\www\js
Extract: federation.js
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_federation_management-3.11.5\priv\www\js\tmpl
Extract: federation-upstream.ejs
Extract: federation-upstreams.ejs
Extract: federation.ejs
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_jms_topic_exchange-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_jms_topic_exchange-3.11.5\ebin
Extract: rabbit_jms_topic_exchange.beam
Extract: rabbitmq_jms_topic_exchange.app
Extract: sjx_evaluator.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_jms_topic_exchange-3.11.5\include
Extract: rabbit_jms_topic_exchange.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management-3.11.5\ebin
Extract: rabbit_mgmt_app.beam
Extract: rabbit_mgmt_cors.beam
Extract: rabbit_mgmt_csp.beam
Extract: rabbit_mgmt_db.beam
Extract: rabbit_mgmt_db_cache.beam
Extract: rabbit_mgmt_db_cache_sup.beam
Extract: rabbit_mgmt_dispatcher.beam
Extract: rabbit_mgmt_extension.beam
Extract: rabbit_mgmt_headers.beam
Extract: rabbit_mgmt_hsts.beam
Extract: rabbit_mgmt_load_definitions.beam
Extract: rabbit_mgmt_reset_handler.beam
Extract: rabbit_mgmt_stats.beam
Extract: rabbit_mgmt_sup.beam
Extract: rabbit_mgmt_sup_sup.beam
Extract: rabbit_mgmt_util.beam
Extract: rabbit_mgmt_wm_aliveness_test.beam
Extract: rabbit_mgmt_wm_auth.beam
Extract: rabbit_mgmt_wm_auth_attempts.beam
Extract: rabbit_mgmt_wm_binding.beam
Extract: rabbit_mgmt_wm_bindings.beam
Extract: rabbit_mgmt_wm_channel.beam
Extract: rabbit_mgmt_wm_channels.beam
Extract: rabbit_mgmt_wm_channels_vhost.beam
Extract: rabbit_mgmt_wm_cluster_name.beam
Extract: rabbit_mgmt_wm_connection.beam
Extract: rabbit_mgmt_wm_connection_channels.beam
Extract: rabbit_mgmt_wm_connection_user_name.beam
Extract: rabbit_mgmt_wm_connections.beam
Extract: rabbit_mgmt_wm_connections_vhost.beam
Extract: rabbit_mgmt_wm_consumers.beam
Extract: rabbit_mgmt_wm_definitions.beam
Extract: rabbit_mgmt_wm_environment.beam
Extract: rabbit_mgmt_wm_exchange.beam
Extract: rabbit_mgmt_wm_exchange_publish.beam
Extract: rabbit_mgmt_wm_exchanges.beam
Extract: rabbit_mgmt_wm_extensions.beam
Extract: rabbit_mgmt_wm_feature_flag_enable.beam
Extract: rabbit_mgmt_wm_feature_flags.beam
Extract: rabbit_mgmt_wm_global_parameter.beam
Extract: rabbit_mgmt_wm_global_parameters.beam
Extract: rabbit_mgmt_wm_health_check_alarms.beam
Extract: rabbit_mgmt_wm_health_check_certificate_expiration.beam
Extract: rabbit_mgmt_wm_health_check_local_alarms.beam
Extract: rabbit_mgmt_wm_health_check_node_is_mirror_sync_critical.beam
Extract: rabbit_mgmt_wm_health_check_node_is_quorum_critical.beam
Extract: rabbit_mgmt_wm_health_check_port_listener.beam
Extract: rabbit_mgmt_wm_health_check_protocol_listener.beam
Extract: rabbit_mgmt_wm_health_check_virtual_hosts.beam
Extract: rabbit_mgmt_wm_healthchecks.beam
Extract: rabbit_mgmt_wm_limit.beam
Extract: rabbit_mgmt_wm_limits.beam
Extract: rabbit_mgmt_wm_login.beam
Extract: rabbit_mgmt_wm_node.beam
Extract: rabbit_mgmt_wm_node_memory.beam
Extract: rabbit_mgmt_wm_node_memory_ets.beam
Extract: rabbit_mgmt_wm_nodes.beam
Extract: rabbit_mgmt_wm_operator_policies.beam
Extract: rabbit_mgmt_wm_operator_policy.beam
Extract: rabbit_mgmt_wm_overview.beam
Extract: rabbit_mgmt_wm_parameter.beam
Extract: rabbit_mgmt_wm_parameters.beam
Extract: rabbit_mgmt_wm_permission.beam
Extract: rabbit_mgmt_wm_permissions.beam
Extract: rabbit_mgmt_wm_permissions_user.beam
Extract: rabbit_mgmt_wm_permissions_vhost.beam
Extract: rabbit_mgmt_wm_policies.beam
Extract: rabbit_mgmt_wm_policy.beam
Extract: rabbit_mgmt_wm_queue.beam
Extract: rabbit_mgmt_wm_queue_actions.beam
Extract: rabbit_mgmt_wm_queue_get.beam
Extract: rabbit_mgmt_wm_queue_purge.beam
Extract: rabbit_mgmt_wm_queues.beam
Extract: rabbit_mgmt_wm_rebalance_queues.beam
Extract: rabbit_mgmt_wm_redirect.beam
Extract: rabbit_mgmt_wm_reset.beam
Extract: rabbit_mgmt_wm_static.beam
Extract: rabbit_mgmt_wm_topic_permission.beam
Extract: rabbit_mgmt_wm_topic_permissions.beam
Extract: rabbit_mgmt_wm_topic_permissions_user.beam
Extract: rabbit_mgmt_wm_topic_permissions_vhost.beam
Extract: rabbit_mgmt_wm_user.beam
Extract: rabbit_mgmt_wm_user_limit.beam
Extract: rabbit_mgmt_wm_user_limits.beam
Extract: rabbit_mgmt_wm_users.beam
Extract: rabbit_mgmt_wm_users_bulk_delete.beam
Extract: rabbit_mgmt_wm_vhost.beam
Extract: rabbit_mgmt_wm_vhost_restart.beam
Extract: rabbit_mgmt_wm_vhosts.beam
Extract: rabbit_mgmt_wm_whoami.beam
Extract: rabbitmq_management.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management-3.11.5\include
Extract: rabbit_mgmt.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management-3.11.5\priv\schema
Extract: rabbitmq_management.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management-3.11.5\priv\www
Extract: favicon.ico
Extract: index.html
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management-3.11.5\priv\www\api
Extract: index.html
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management-3.11.5\priv\www\cli
Extract: index.html
Extract: rabbitmqadmin
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management-3.11.5\priv\www\css
Extract: evil.css
Extract: main.css
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management-3.11.5\priv\www\img
Extract: bg-binary.png
Extract: bg-green-dark.png
Extract: bg-red-dark.png
Extract: bg-red.png
Extract: bg-yellow-dark.png
Extract: collapse.png
Extract: expand.png
Extract: rabbitmqlogo-master-copy.svg
Extract: rabbitmqlogo.svg
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management-3.11.5\priv\www\js
Extract: base64.js
Extract: charts.js
Extract: dispatcher.js
Extract: ejs-1.0.js
Extract: ejs-1.0.min.js
Extract: excanvas.js
Extract: excanvas.min.js
Extract: formatters.js
Extract: global.js
Extract: jquery-3.5.1.js
Extract: jquery-3.5.1.min.js
Extract: jquery.flot-0.8.1.js
Extract: jquery.flot-0.8.1.min.js
Extract: jquery.flot-0.8.1.time.js
Extract: jquery.flot-0.8.1.time.min.js
Extract: json2-2016.10.28.js
Extract: main.js
Extract: prefs.js
Extract: sammy-0.7.6.js
Extract: sammy-0.7.6.min.js
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management-3.11.5\priv\www\js\oidc-oauth
Extract: helper.js
Extract: login-callback.html
Extract: logout-callback.html
Extract: oidc-client-ts.js
Extract: oidc-client-ts.js.map
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management-3.11.5\priv\www\js\tmpl
Extract: 404.ejs
Extract: add-binding.ejs
Extract: binary.ejs
Extract: bindings.ejs
Extract: channel.ejs
Extract: channels-list.ejs
Extract: channels.ejs
Extract: cluster-name.ejs
Extract: columns-options.ejs
Extract: connection.ejs
Extract: connections.ejs
Extract: consumers.ejs
Extract: exchange.ejs
Extract: exchanges.ejs
Extract: feature-flags.ejs
Extract: layout.ejs
Extract: limits.ejs
Extract: list-exchanges.ejs
Extract: login.ejs
Extract: login_oauth.ejs
Extract: memory-bar.ejs
Extract: memory-table.ejs
Extract: memory.ejs
Extract: messages.ejs
Extract: msg-detail-deliveries.ejs
Extract: msg-detail-publishes.ejs
Extract: node.ejs
Extract: overview.ejs
Extract: partition.ejs
Extract: permissions.ejs
Extract: policies.ejs
Extract: policy.ejs
Extract: popup.ejs
Extract: publish.ejs
Extract: queue.ejs
Extract: queues.ejs
Extract: rate-options.ejs
Extract: registry.ejs
Extract: status.ejs
Extract: topic-permissions.ejs
Extract: user.ejs
Extract: users.ejs
Extract: vhost.ejs
Extract: vhosts.ejs
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management_agent-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management_agent-3.11.5\ebin
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.ResetStatsDbCommand.beam
Extract: exometer_slide.beam
Extract: rabbit_mgmt_agent_app.beam
Extract: rabbit_mgmt_agent_config.beam
Extract: rabbit_mgmt_agent_sup.beam
Extract: rabbit_mgmt_agent_sup_sup.beam
Extract: rabbit_mgmt_data.beam
Extract: rabbit_mgmt_data_compat.beam
Extract: rabbit_mgmt_db_handler.beam
Extract: rabbit_mgmt_external_stats.beam
Extract: rabbit_mgmt_ff.beam
Extract: rabbit_mgmt_format.beam
Extract: rabbit_mgmt_gc.beam
Extract: rabbit_mgmt_metrics_collector.beam
Extract: rabbit_mgmt_metrics_gc.beam
Extract: rabbit_mgmt_storage.beam
Extract: rabbitmq_management_agent.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management_agent-3.11.5\include
Extract: rabbit_mgmt_agent.hrl
Extract: rabbit_mgmt_metrics.hrl
Extract: rabbit_mgmt_records.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management_agent-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_management_agent-3.11.5\priv\schema
Extract: rabbitmq_management_agent.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_mqtt-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_mqtt-3.11.5\ebin
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.DecommissionMqttNodeCommand.beam
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.ListMqttConnectionsCommand.beam
Extract: mqtt_machine.beam
Extract: mqtt_machine_v0.beam
Extract: mqtt_node.beam
Extract: rabbit_mqtt.beam
Extract: rabbit_mqtt_collector.beam
Extract: rabbit_mqtt_connection_info.beam
Extract: rabbit_mqtt_connection_sup.beam
Extract: rabbit_mqtt_frame.beam
Extract: rabbit_mqtt_internal_event_handler.beam
Extract: rabbit_mqtt_processor.beam
Extract: rabbit_mqtt_reader.beam
Extract: rabbit_mqtt_retained_msg_store.beam
Extract: rabbit_mqtt_retained_msg_store_dets.beam
Extract: rabbit_mqtt_retained_msg_store_ets.beam
Extract: rabbit_mqtt_retained_msg_store_noop.beam
Extract: rabbit_mqtt_retainer.beam
Extract: rabbit_mqtt_retainer_sup.beam
Extract: rabbit_mqtt_sup.beam
Extract: rabbit_mqtt_util.beam
Extract: rabbitmq_mqtt.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_mqtt-3.11.5\include
Extract: mqtt_machine.hrl
Extract: mqtt_machine_v0.hrl
Extract: rabbit_mqtt.hrl
Extract: rabbit_mqtt_frame.hrl
Extract: rabbit_mqtt_retained_msg_store.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_mqtt-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_mqtt-3.11.5\priv\schema
Extract: rabbitmq_mqtt.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_aws-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_aws-3.11.5\ebin
Extract: rabbit_peer_discovery_aws.beam
Extract: rabbitmq_peer_discovery_aws.app
Extract: rabbitmq_peer_discovery_aws.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_aws-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_aws-3.11.5\priv\schema
Extract: rabbitmq_peer_discovery_aws.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_common-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_common-3.11.5\ebin
Extract: rabbit_peer_discovery_cleanup.beam
Extract: rabbit_peer_discovery_common_app.beam
Extract: rabbit_peer_discovery_common_sup.beam
Extract: rabbit_peer_discovery_config.beam
Extract: rabbit_peer_discovery_httpc.beam
Extract: rabbit_peer_discovery_util.beam
Extract: rabbitmq_peer_discovery_common.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_common-3.11.5\include
Extract: rabbit_peer_discovery.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_common-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_common-3.11.5\priv\schema
Extract: rabbitmq_peer_discovery_common.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_consul-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_consul-3.11.5\ebin
Extract: rabbit_peer_discovery_consul.beam
Extract: rabbitmq_peer_discovery_consul.app
Extract: rabbitmq_peer_discovery_consul.beam
Extract: rabbitmq_peer_discovery_consul_app.beam
Extract: rabbitmq_peer_discovery_consul_health_check_helper.beam
Extract: rabbitmq_peer_discovery_consul_sup.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_consul-3.11.5\include
Extract: rabbit_peer_discovery_consul.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_consul-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_consul-3.11.5\priv\schema
Extract: rabbitmq_peer_discovery_consul.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_etcd-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_etcd-3.11.5\ebin
Extract: rabbit_peer_discovery_etcd.beam
Extract: rabbitmq_peer_discovery_etcd.app
Extract: rabbitmq_peer_discovery_etcd.beam
Extract: rabbitmq_peer_discovery_etcd_app.beam
Extract: rabbitmq_peer_discovery_etcd_sup.beam
Extract: rabbitmq_peer_discovery_etcd_v3_client.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_etcd-3.11.5\include
Extract: rabbit_peer_discovery_etcd.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_etcd-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_etcd-3.11.5\priv\schema
Extract: rabbitmq_peer_discovery_etcd.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_k8s-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_k8s-3.11.5\ebin
Extract: rabbit_peer_discovery_k8s.beam
Extract: rabbitmq_peer_discovery_k8s.app
Extract: rabbitmq_peer_discovery_k8s.beam
Extract: rabbitmq_peer_discovery_k8s_app.beam
Extract: rabbitmq_peer_discovery_k8s_node_monitor.beam
Extract: rabbitmq_peer_discovery_k8s_sup.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_k8s-3.11.5\include
Extract: rabbit_peer_discovery_k8s.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_k8s-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_peer_discovery_k8s-3.11.5\priv\schema
Extract: rabbitmq_peer_discovery_k8s.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_prelaunch-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_prelaunch-3.11.5\ebin
Extract: rabbit_boot_state.beam
Extract: rabbit_boot_state_sup.beam
Extract: rabbit_boot_state_systemd.beam
Extract: rabbit_boot_state_xterm_titlebar.beam
Extract: rabbit_logger_fmt_helpers.beam
Extract: rabbit_logger_json_fmt.beam
Extract: rabbit_logger_std_h.beam
Extract: rabbit_logger_text_fmt.beam
Extract: rabbit_prelaunch.beam
Extract: rabbit_prelaunch_app.beam
Extract: rabbit_prelaunch_conf.beam
Extract: rabbit_prelaunch_dist.beam
Extract: rabbit_prelaunch_early_logging.beam
Extract: rabbit_prelaunch_erlang_compat.beam
Extract: rabbit_prelaunch_errors.beam
Extract: rabbit_prelaunch_file.beam
Extract: rabbit_prelaunch_sighandler.beam
Extract: rabbit_prelaunch_sup.beam
Extract: rabbitmq_prelaunch.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_prometheus-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_prometheus-3.11.5\ebin
Extract: prometheus_process_collector.beam
Extract: prometheus_rabbitmq_alarm_metrics_collector.beam
Extract: prometheus_rabbitmq_core_metrics_collector.beam
Extract: prometheus_rabbitmq_global_metrics_collector.beam
Extract: rabbit_prometheus_app.beam
Extract: rabbit_prometheus_dispatcher.beam
Extract: rabbit_prometheus_handler.beam
Extract: rabbitmq_prometheus.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_prometheus-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_prometheus-3.11.5\priv\schema
Extract: rabbitmq_prometheus.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_random_exchange-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_random_exchange-3.11.5\ebin
Extract: rabbit_exchange_type_random.beam
Extract: rabbitmq_random_exchange.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_random_exchange-3.11.5\include
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_recent_history_exchange-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_recent_history_exchange-3.11.5\ebin
Extract: rabbit_exchange_type_recent_history.beam
Extract: rabbitmq_recent_history_exchange.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_recent_history_exchange-3.11.5\include
Extract: rabbit_recent_history.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_sharding-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_sharding-3.11.5\ebin
Extract: rabbit_sharding_exchange_decorator.beam
Extract: rabbit_sharding_exchange_type_modulus_hash.beam
Extract: rabbit_sharding_interceptor.beam
Extract: rabbit_sharding_policy_validator.beam
Extract: rabbit_sharding_shard.beam
Extract: rabbit_sharding_util.beam
Extract: rabbitmq_sharding.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_shovel-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_shovel-3.11.5\ebin
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.DeleteShovelCommand.beam
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.RestartShovelCommand.beam
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.ShovelStatusCommand.beam
Extract: rabbit_amqp091_shovel.beam
Extract: rabbit_amqp10_shovel.beam
Extract: rabbit_log_shovel.beam
Extract: rabbit_shovel.beam
Extract: rabbit_shovel_behaviour.beam
Extract: rabbit_shovel_config.beam
Extract: rabbit_shovel_dyn_worker_sup.beam
Extract: rabbit_shovel_dyn_worker_sup_sup.beam
Extract: rabbit_shovel_locks.beam
Extract: rabbit_shovel_parameters.beam
Extract: rabbit_shovel_status.beam
Extract: rabbit_shovel_sup.beam
Extract: rabbit_shovel_util.beam
Extract: rabbit_shovel_worker.beam
Extract: rabbit_shovel_worker_sup.beam
Extract: rabbitmq_shovel.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_shovel-3.11.5\include
Extract: logging.hrl
Extract: rabbit_shovel.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_shovel_management-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_shovel_management-3.11.5\ebin
Extract: rabbit_shovel_mgmt.beam
Extract: rabbit_shovel_mgmt_util.beam
Extract: rabbitmq_shovel_management.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_shovel_management-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_shovel_management-3.11.5\priv\www
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_shovel_management-3.11.5\priv\www\js
Extract: shovel.js
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_shovel_management-3.11.5\priv\www\js\tmpl
Extract: dynamic-shovel.ejs
Extract: dynamic-shovels.ejs
Extract: shovels.ejs
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stomp-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stomp-3.11.5\ebin
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.ListStompConnectionsCommand.beam
Extract: rabbit_stomp.beam
Extract: rabbit_stomp_client_sup.beam
Extract: rabbit_stomp_connection_info.beam
Extract: rabbit_stomp_frame.beam
Extract: rabbit_stomp_internal_event_handler.beam
Extract: rabbit_stomp_processor.beam
Extract: rabbit_stomp_reader.beam
Extract: rabbit_stomp_sup.beam
Extract: rabbit_stomp_util.beam
Extract: rabbitmq_stomp.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stomp-3.11.5\include
Extract: rabbit_stomp.hrl
Extract: rabbit_stomp_frame.hrl
Extract: rabbit_stomp_headers.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stomp-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stomp-3.11.5\priv\schema
Extract: rabbitmq_stomp.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream-3.11.5\ebin
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.AddSuperStreamCommand.beam
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.DeleteSuperStreamCommand.beam
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.ListStreamConnectionsCommand.beam
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.ListStreamConsumerGroupsCommand.beam
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.ListStreamConsumersCommand.beam
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.ListStreamGroupConsumersCommand.beam
Extract: Elixir.RabbitMQ.CLI.Ctl.Commands.ListStreamPublishersCommand.beam
Extract: rabbit_stream.beam
Extract: rabbit_stream_connection_sup.beam
Extract: rabbit_stream_manager.beam
Extract: rabbit_stream_metrics.beam
Extract: rabbit_stream_metrics_gc.beam
Extract: rabbit_stream_reader.beam
Extract: rabbit_stream_sup.beam
Extract: rabbit_stream_utils.beam
Extract: rabbitmq_stream.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream-3.11.5\include
Extract: rabbit_stream_metrics.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream-3.11.5\priv\schema
Extract: rabbitmq_stream.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream_common-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream_common-3.11.5\ebin
Extract: rabbit_stream_core.beam
Extract: rabbitmq_stream_common.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream_common-3.11.5\include
Extract: rabbit_stream.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream_management-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream_management-3.11.5\ebin
Extract: rabbit_stream_connection_consumers_mgmt.beam
Extract: rabbit_stream_connection_mgmt.beam
Extract: rabbit_stream_connection_publishers_mgmt.beam
Extract: rabbit_stream_connections_mgmt.beam
Extract: rabbit_stream_connections_vhost_mgmt.beam
Extract: rabbit_stream_consumers_mgmt.beam
Extract: rabbit_stream_management_utils.beam
Extract: rabbit_stream_mgmt_db.beam
Extract: rabbit_stream_publishers_mgmt.beam
Extract: rabbitmq_stream_management.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream_management-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream_management-3.11.5\priv\www
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream_management-3.11.5\priv\www\js
Extract: stream.js
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_stream_management-3.11.5\priv\www\js\tmpl
Extract: streamConnection.ejs
Extract: streamConnections.ejs
Extract: streamConsumersList.ejs
Extract: streamPublishersList.ejs
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_top-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_top-3.11.5\ebin
Extract: rabbit_top_app.beam
Extract: rabbit_top_extension.beam
Extract: rabbit_top_sup.beam
Extract: rabbit_top_util.beam
Extract: rabbit_top_wm_ets_tables.beam
Extract: rabbit_top_wm_process.beam
Extract: rabbit_top_wm_processes.beam
Extract: rabbit_top_worker.beam
Extract: rabbitmq_top.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_top-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_top-3.11.5\priv\www
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_top-3.11.5\priv\www\js
Extract: top.js
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_top-3.11.5\priv\www\js\tmpl
Extract: ets_tables.ejs
Extract: process.ejs
Extract: processes.ejs
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_tracing-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_tracing-3.11.5\ebin
Extract: rabbit_tracing_app.beam
Extract: rabbit_tracing_consumer.beam
Extract: rabbit_tracing_consumer_sup.beam
Extract: rabbit_tracing_files.beam
Extract: rabbit_tracing_mgmt.beam
Extract: rabbit_tracing_sup.beam
Extract: rabbit_tracing_traces.beam
Extract: rabbit_tracing_util.beam
Extract: rabbit_tracing_wm_file.beam
Extract: rabbit_tracing_wm_files.beam
Extract: rabbit_tracing_wm_trace.beam
Extract: rabbit_tracing_wm_traces.beam
Extract: rabbitmq_tracing.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_tracing-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_tracing-3.11.5\priv\www
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_tracing-3.11.5\priv\www\js
Extract: tracing.js
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_tracing-3.11.5\priv\www\js\tmpl
Extract: traces.ejs
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_trust_store-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_trust_store-3.11.5\ebin
Extract: rabbit_trust_store.beam
Extract: rabbit_trust_store_app.beam
Extract: rabbit_trust_store_certificate_provider.beam
Extract: rabbit_trust_store_file_provider.beam
Extract: rabbit_trust_store_http_provider.beam
Extract: rabbit_trust_store_sup.beam
Extract: rabbitmq_trust_store.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_trust_store-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_trust_store-3.11.5\priv\schema
Extract: rabbitmq_trust_store.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_dispatch-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_dispatch-3.11.5\ebin
Extract: rabbit_cowboy_middleware.beam
Extract: rabbit_cowboy_redirect.beam
Extract: rabbit_cowboy_stream_h.beam
Extract: rabbit_web_dispatch.beam
Extract: rabbit_web_dispatch_app.beam
Extract: rabbit_web_dispatch_listing_handler.beam
Extract: rabbit_web_dispatch_registry.beam
Extract: rabbit_web_dispatch_sup.beam
Extract: rabbit_web_dispatch_util.beam
Extract: rabbitmq_web_dispatch.app
Extract: webmachine_log.beam
Extract: webmachine_log_handler.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_mqtt-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_mqtt-3.11.5\ebin
Extract: rabbit_web_mqtt_app.beam
Extract: rabbit_web_mqtt_connection_info.beam
Extract: rabbit_web_mqtt_connection_sup.beam
Extract: rabbit_web_mqtt_handler.beam
Extract: rabbit_web_mqtt_middleware.beam
Extract: rabbit_web_mqtt_stream_handler.beam
Extract: rabbitmq_web_mqtt.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_mqtt-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_mqtt-3.11.5\priv\schema
Extract: rabbitmq_web_mqtt.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_mqtt_examples-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_mqtt_examples-3.11.5\ebin
Extract: rabbit_web_mqtt_examples_app.beam
Extract: rabbitmq_web_mqtt_examples.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_mqtt_examples-3.11.5\priv
Extract: bunny.html
Extract: bunny.png
Extract: echo.html
Extract: index.html
Extract: main.css
Extract: mqttws31.js
Extract: pencil.cur
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_stomp-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_stomp-3.11.5\ebin
Extract: rabbit_web_stomp_app.beam
Extract: rabbit_web_stomp_connection_sup.beam
Extract: rabbit_web_stomp_handler.beam
Extract: rabbit_web_stomp_internal_event_handler.beam
Extract: rabbit_web_stomp_listener.beam
Extract: rabbit_web_stomp_middleware.beam
Extract: rabbit_web_stomp_stream_handler.beam
Extract: rabbit_web_stomp_sup.beam
Extract: rabbitmq_web_stomp.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_stomp-3.11.5\priv
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_stomp-3.11.5\priv\schema
Extract: rabbitmq_web_stomp.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_stomp_examples-3.11.5
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_stomp_examples-3.11.5\ebin
Extract: rabbit_web_stomp_examples_app.beam
Extract: rabbitmq_web_stomp_examples.app
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\rabbitmq_web_stomp_examples-3.11.5\priv
Extract: bunny.html
Extract: bunny.png
Extract: echo.html
Extract: index.html
Extract: main.css
Extract: pencil.cur
Extract: stomp.js
Extract: temp-queue.html
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\ranch-2.1.0
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\ranch-2.1.0\ebin
Extract: ranch.app
Extract: ranch.appup
Extract: ranch.beam
Extract: ranch_acceptor.beam
Extract: ranch_acceptors_sup.beam
Extract: ranch_app.beam
Extract: ranch_conns_sup.beam
Extract: ranch_conns_sup_sup.beam
Extract: ranch_crc32c.beam
Extract: ranch_embedded_sup.beam
Extract: ranch_listener_sup.beam
Extract: ranch_protocol.beam
Extract: ranch_proxy_header.beam
Extract: ranch_server.beam
Extract: ranch_server_proxy.beam
Extract: ranch_ssl.beam
Extract: ranch_sup.beam
Extract: ranch_tcp.beam
Extract: ranch_transport.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\recon-2.5.2
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\recon-2.5.2\ebin
Extract: recon.app
Extract: recon.beam
Extract: recon_alloc.beam
Extract: recon_lib.beam
Extract: recon_map.beam
Extract: recon_rec.beam
Extract: recon_trace.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\redbug-2.0.7
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\redbug-2.0.7\ebin
Extract: redbug.app
Extract: redbug.beam
Extract: redbug_compiler.beam
Extract: redbug_dtop.beam
Extract: redbug_lexer.beam
Extract: redbug_parser.beam
Extract: redbug_targ.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\seshat-0.4.0
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\seshat-0.4.0\ebin
Extract: seshat.app
Extract: seshat.beam
Extract: seshat_app.beam
Extract: seshat_counters_server.beam
Extract: seshat_sup.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\stdout_formatter-0.2.4
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\stdout_formatter-0.2.4\ebin
Extract: stdout_formatter.app
Extract: stdout_formatter.beam
Extract: stdout_formatter_paragraph.beam
Extract: stdout_formatter_table.beam
Extract: stdout_formatter_utils.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\stdout_formatter-0.2.4\include
Extract: stdout_formatter.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\syslog-4.0.0
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\syslog-4.0.0\ebin
Extract: syslog.app
Extract: syslog.beam
Extract: syslog_error_h.beam
Extract: syslog_lager_backend.beam
Extract: syslog_lib.beam
Extract: syslog_logger.beam
Extract: syslog_logger_h.beam
Extract: syslog_monitor.beam
Extract: syslog_rfc3164.beam
Extract: syslog_rfc5424.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\syslog-4.0.0\include
Extract: syslog.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\sysmon_handler-1.3.0
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\sysmon_handler-1.3.0\ebin
Extract: sysmon_handler.app
Extract: sysmon_handler_app.beam
Extract: sysmon_handler_example_handler.beam
Extract: sysmon_handler_filter.beam
Extract: sysmon_handler_sup.beam
Extract: sysmon_handler_testhandler.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\sysmon_handler-1.3.0\include
Extract: sysmon_handler.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\sysmon_handler-1.3.0\priv
Extract: sysmon_handler.schema
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\systemd-0.6.1
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\systemd-0.6.1\ebin
Extract: systemd.app
Extract: systemd.beam
Extract: systemd_app.beam
Extract: systemd_journal_h.beam
Extract: systemd_kmsg_formatter.beam
Extract: systemd_protocol.beam
Extract: systemd_socket.beam
Extract: systemd_sup.beam
Extract: systemd_watchdog.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\systemd-0.6.1\include
Extract: systemd.hrl
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\thoas-0.4.0
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins\thoas-0.4.0\ebin
Extract: thoas.app
Extract: thoas.beam
Extract: thoas_decode.beam
Extract: thoas_encode.beam
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\plugins
Output folder: C:\Users\eodum\AppData\Roaming\RabbitMQ
Created uninstaller: C:\Program Files\RabbitMQ Server\uninstall.exe
Installing RabbitMQ service...
C:\Program Files\Erlang OTP\erts-13.1.3\bin\erlsrv: Service RabbitMQ added to system.
Delete file: C:\Users\eodum\.erlang.cookie
Create folder: C:\Users\eodum\AppData\Roaming\RabbitMQ\log
Create folder: C:\Users\eodum\AppData\Roaming\RabbitMQ\db
Create folder: C:\Users\eodum\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RabbitMQ Server
Create shortcut: C:\Users\eodum\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RabbitMQ Server\Uninstall RabbitMQ.lnk
Create shortcut: C:\Users\eodum\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RabbitMQ Server\RabbitMQ Plugins.lnk
Create shortcut: C:\Users\eodum\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RabbitMQ Server\RabbitMQ Logs.lnk
Create shortcut: C:\Users\eodum\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RabbitMQ Server\RabbitMQ Database Directory.lnk
Create shortcut: C:\Users\eodum\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RabbitMQ Server\RabbitMQ Service - (re)install.lnk
Create shortcut: C:\Users\eodum\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RabbitMQ Server\RabbitMQ Service - remove.lnk
Create shortcut: C:\Users\eodum\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RabbitMQ Server\RabbitMQ Service - start.lnk
Create shortcut: C:\Users\eodum\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RabbitMQ Server\RabbitMQ Service - stop.lnk
Output folder: C:\Program Files\RabbitMQ Server\rabbitmq_server-3.11.5\sbin
Create shortcut: C:\Users\eodum\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RabbitMQ Server\RabbitMQ Command Prompt (sbin dir).lnk
Output folder: C:\Program Files\RabbitMQ Server
Completed


RabbitMQ is Advanced Message Queuing Protocol (AMQP), It should be installed and running in your system where product 
C:\Program Files\RabbitMQ Server
service will be deployed. Though this example is for localhost you need to install in your local computer and by default 
run in ``http://localhost:15672/``  
Username: guest  
Password: guest
  
##### [Mac OS]  
I have prepared a bash file **install-rabbitmq-macOS.sh** to install RabbitMQ in MacOS. Type `bash install-rabbitmq-macOS.sh` in 
your system terminal and after installation completed run `rabbitmq-server` command to start RabbitMQ.

##### [Ubuntu OS]
Check this for [Installing on Debian and Ubuntu](https://www.rabbitmq.com/install-debian.html)  

RabbitMQ commands for ubuntu  
--to start `sudo service rabbitmq-server start`  
--to restart `sudo service rabbitmq-server restart`  
--to stop `sudo service rabbitmq-server stop`  
--to check status `sudo service rabbitmq-server status`


##### [Windows]  
Check this for [Installing on Windows](https://www.rabbitmq.com/install-windows.html#installer)

### 4. Lombok
Lombok plugin should be installed in you IDE otherwise IDE will catch code error. I used Intellij Idea and I had to install 
lombok plugin.

### 5. Install Node, Angular and Angular CLI
In my system I used
````   
Angular CLI: 8.3.25
Node: 12.13.1
Angular: 8.2.14 
````
You need to install Node 12 or higher version and Angular 8 or higher version to run microservice-ui application.

## Run microservice-ui application
It's an angular based user interface application for these microservice frontend. It's not any high functional user interface 
I just tried to consume the backend services from here. You can check all the api just from **Postman**.  

Open terminal run below command to launch microservice-ui application
````
cd microservice-ui/
npm install
ng s --port 3000 --open
````
It will open a new tab in your browser with **http://localhost:3000/store** url as frontend application.
When it opens it calls ``http://localhost:8000/product-service/products`` by default to fetch all product list. 
It will not respond any products because backend services are not started yet.   

![store home](readme-images/store-home.png)

UI application is ready, Now we need to run it's backend applications. 
All the backend applications are developed by spring-boot.

## Run service-registry application
service-registry is the application where all microservice instances will register with a service id. When a service wants 
to call another service, it will ask service-registry by service id to what instances are currently running for that service id. 
service-registry check the instances and pass the request to any active the instance dynamically. This is called service 
discovery. The advantage is no need to hard coded instance ip address, service registry always updates itself, if one instance 
goes down, It removes that instance from the registry. 
- **Eureka** is used to achieve this functionality

Open a new terminal and run below command to launch service-registry
````
cd service-registry/
mvn clean install
mvn spring-boot:run
````
service-registry will launch in http://localhost:8761/  

![service registry](readme-images/service-registry.png)

Right now only service-registry is registered with Eureka. In your system it will show your ip address.  
All the backend application will register here one by one after launching and service-registry will show like this. 

![all registered service](readme-images/all-registered-service.png)

## Run api-gateway application
api-gateway application is the service for facing other services. Just like the entry point to get any service. Receive 
all the request from user and delegates the request to the appropriate service. 
- **Zuul** is used to achieve this functionality

Open a new terminal and run below command to run api gateway
````
cd api-gateway/
mvn clean install
mvn spring-boot:run
````
The application will run in ``http://localhost:8000/``.

api-gateway is configured such a way that we can call product-service and offer-service api through api-gateway.   
Like - when we call with a specific url pattern api-gateway will forward the request to the corresponding service based 
on that url pattern.  

| API             | REST Method   | Api-gateway request                                       | Forwarded service   | Forwarded URL                      |
|-----------------|:--------------|:----------------------------------------------------------|:--------------------|:-----------------------------------|
|Get all products |GET            |``http://localhost:8000/product-service/products``         | product-service     | ``http://localhost:8081/products`` |    
|Add new product  |POST           |``http://localhost:8000/product-service/products``         | product-service     | ``http://localhost:8081/products`` |    
|Update price     |PUT            |``http://localhost:8000/product-service/products/addPrice``| product-service     | ``http://localhost:8081/products`` |    
|Add offer        |POST           |``http://localhost:8000/offer-service/offer``              | offer-service       | ``http://localhost:8082/offer``    |

Above table contains all the used api in this entire application.

If we have multiple instance for product-service like ``http://localhost:8081`` and ``http://localhost:8180``.
So when we call ``http://localhost:8000/product-service/products`` api gateway will forward it to one of the two instance 
of product-service as load balancing in Round-robin order since Zuul api-gateway use Ribbon load balancer.
Api gateway frequently keep updated all available instance list of a service from eureka server.  
  
**you can create as many as instance you need for product-service as well as offer-service api-gateway will handle it smartly.**

So we can say that api-gateway is the front door of our backend application by passing this we need to enter kitchen or 
washroom whatever. [Bad joke LOL]

## Run Product service
Open a new terminal and run below command
````
cd product-service/
mvn clean install
````
The ``mvn clean install`` command will create a ``product-service-0.0.1-SNAPSHOT.jar`` inside ``target`` directory. 
We will run two product service instance by two different port. Run below command in a separate terminal
````
cd target/
java -jar product-service-0.0.1-SNAPSHOT.jar --server.port=8081
````
Above command will run product-service in 8081 port.

Run another instance of product-service in 8180 port by running below command in another terminal
````
java -jar product-service-0.0.1-SNAPSHOT.jar --server.port=8180
````
After few seconds you can see there are 2 instance running for product-service which is registered with Eureka server in http://localhost:8761/

***Note:** Both instance are running as separate application but they are using same database.*

Access product-service data source console in browser by
`localhost:8081/h2`  
To connect product data source h2 console use below credentials   
JDBC URL  : `jdbc:h2:~/product`  
User Name : `root`  
Password  : `root`  

Check product table. Right now there is no products.  
Let's add a new product by calling `localhost:8000/product-service/products` **POST** endpoint with below body in postman.
````
{
	"productCode": "TW1",
	"productTitle": "Titan",
	"imageUrl": "https://staticimg.titan.co.in/Titan/Catalog/90014KC01J_1.jpg?pView=pdp",
	"price": 30
}
````
Or in microservice-ui press ``Add New Product`` button and fill the pop-up window with above value then press ``Add`` to 
add new product.   

![add new product](readme-images/add-new-product.png)

After adding new product the window will be refreshed and you will see like this   

![after adding one product](readme-images/added-first-product.png)
maf 
Let's add two more new products

````
{
	"productCode": "FW1",
	"productTitle": "Fastrack",
	"imageUrl": "https://staticimg.titan.co.in/Fastrack/Catalog/38051SP01_2.jpg",
	"price": 30
}
````

````
{
	"productCode": "RW1",
	"productTitle": "Rolex",
	"imageUrl": "https://www.avantijewellers.co.uk/images/rolex-watches-pre-owned-mens-rolex-oyster-precision-vintage-watch-p3003-7660_medium.jpg",
	"price": null
}
````
So far our browser window like this  

![all added products](readme-images/all-product-added.png)

If you check product table there is three product added with no **discount_offer**. We will add **discount_offer** by 
sending an event notification from other offer-service application.

One additional information, I have not added any price when adding *Rolex*. Price can be added or updated later after 
adding any product by ``Add Price`` button.

## Run Offer service
Open separate terminal and run
 ````
 cd offer-service/
 mvn clean install
 mvn spring-boot:run
 ````
Application will run on ``http://localhost:8082/``

Access it's data source console in browser by
`localhost:8082/h2`  
To connect offer data source h2 console use below credentials  
JDBC URL  : `jdbc:h2:~/offer`  
User Name : `root`  
Password  : `root`

Check offer table and there is no offer right now.  
Let's add a offer for *product_id = 1* by calling `http://localhost:8000/offer-service/offer` POST endpoint with below body in postman
````
{
	"productId": 1,
	"discountOffer": 10
}
````
Or in microservice-ui press ``Add Discount`` button and fill the pop-up window with above value then press ``Add`` to 
add discount for *product_id = 1*  

![add offer](readme-images/add-offer.png)

If you check offer table there is an offer recorded for *product_id = 1*  and browser will show  

![offer added](readme-images/offer-added.png)

Now you are seeing *Payable: $27* for *product_id = 1* after calculating discount.

**Alert! I am going to show you an interesting thing**, if you check product table from product-service data source 
where *product_id = 1* is updated by discount_offer = 10 and current_price = 27.

**Note:** Here Offer and Product table are from two different database and running on different port.
Because both service are using different database. 

Here you called offer-service api and it's added a new offer record in it's own data source as well as updated product 
record where *product_id = 1*. 

### So how is this happened?
From **offer-service** when we add an offer for a specific product, it pushes an event notification to **product-service** 
with discount_offer and **product-service** received the event then update it's own database according to it's own business
logic of the event.

### How service to service event working?
Here RabbitMQ is configured with both offer-service and product-service. In offer-service when a offer added it will push 
an event to product-service. RabbitMQ push the events as a queue[one by one serially] order from event producer to event
consumer. For these event offer-service is producer, product-service is consumer. RabbitMQ ensure all event must be pushed 
to consumer if RabbitMQ server is running.

### What will happen if the RabbitMQ server is shutdown?  
No events will be pushed to the consumer. If there is any stored events in RabbitMQ server memory before shutdown those 
will be lost too.  
**Note:** It is possible to overcome this limitation by using persistence mechanism which will keep safe from losing stored events.
This mechanism is not implemented here that's why am skipping the issue.    

### What will happen with the events when all product-service instance are shutdown?
RabbitMQ keeping all the events in itself will wait for any product-service instance when a product-service instance 
relaunched then RabbitMQ will start to push it's events immediately to running product-service instance. You can test it 
by shutting down all product-service by typing ``ctrl + c`` in all product-service launching terminal.  
This functionality is called **Event Driven Development(EDD).** EDD is not a mandatory part of microservice application, 
It's a smart way to do service to service communication. 

Congratulations you have completed the documentation still recheck the workflow diagram that will make you 100% clear now.

# Conclusion
So far this is a complete microservice application. You can enhance the application by adding other service like 
product-service or offer-service(what your requirements demands) by configuring with service-registry and api-gateway.
You also can furnish the application with other handy application like Hystrix, Zipkin, Feign, Sidecar. There are lots 
of handy tools to make the application interactive.  

Hystrix is used here as circuit breaker in api-gateway but microservice-ui still not configured with Hystrix functionality 
yet you can check it in postman by requesting any product-service api by keeping all product-service instance shutdown. 
In this case Hystrix will respond with a default message instead of responding Internal Server Error(500) HTTP status.

# Copyright & License

MIT License, see the link: [LICENSE](https://github.com/hnjaman/complete-microservice-application/blob/master/LICENSE) file for details.
