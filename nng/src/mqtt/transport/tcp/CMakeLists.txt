#
# Copyright 2020 Staysail Systems, Inc. <info@staysail.tech>
# Copyright 2018 Capitar IT Group BV <info@capitar.com>
#
# This software is supplied under the terms of the MIT License, a
# copy of which should be located in the distribution where this
# file was obtained (LICENSE.txt).  A copy of the license may also be
# found online at https://opensource.org/licenses/MIT.
#

# TCP protocol
nng_directory(mqtt)

nng_sources_if(NNG_TRANSPORT_MQTT_TCP mqtt_tcp.c)
nng_headers_if(NNG_TRANSPORT_MQTT_TCP nng/mqtt/transport/tcp/mqtt_tcp.h)
nng_defines_if(NNG_TRANSPORT_MQTT_TCP NNG_TRANSPORT_MQTT_TCP)
