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

if(NNG_TRANSPORT_MQTT_BROKER_TCP)
    nng_sources_if(NNG_TRANSPORT_MQTT_BROKER_TCP broker_tcp.c)
    nng_headers_if(NNG_TRANSPORT_MQTT_BROKER_TCP nng/transport/mqtt/broker_tcp.h)
    nng_defines_if(NNG_TRANSPORT_MQTT_BROKER_TCP NNG_TRANSPORT_MQTT_BROKER_TCP)
endif()