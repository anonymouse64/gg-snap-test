#
# Copyright 2010-2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#

# Modified by Ian Johnson, Canonical ian.johnson@canonical.com for demo purposes

# greengrass_simulated_temp_sensor_run.py
# Demonstrates a simple publish to a topic using Greengrass core sdk
# This lambda function will retrieve underlying platform information and send
# a hello world message along with the platform information to the topic 'hello/world'
# The function will sleep for five seconds, then repeat.  Since the function is
# long-lived it will run forever when deployed to a Greengrass core.  The handler
# will NOT be invoked in our example since the we are executing an infinite loop.

import greengrasssdk
import platform
from threading import Timer
import time
import json
import random


# Creating a greengrass core sdk client
client = greengrasssdk.client('iot-data')

# Retrieving platform information to send from Greengrass Core
my_platform = platform.platform()


# When deployed to a Greengrass core, this code will be executed immediately
# as a long-lived lambda function.  The code will enter the infinite while loop
# below.
# If you execute a 'test' on the Lambda Console, this test will fail by hitting the
# execution timeout of three seconds.  This is expected as this function never returns
# a result.

def greengrass_simulated_temp_sensor_run(currentTemp):
    # this algorithm for generating random temperature + humidity data
    # is basically copied from https://github.com/Azure/iotedge/blob/master/edge-modules/SimulatedTemperatureSensor/src/Program.cs#L184
    # to make "nice" looking data
    if currentTemp > 100:
        currentTemp += (random.random() - 0.5)
    else:
        currentTemp += (-0.25 + (random.random() * 1.5))

    # publish the message on the mqtt topic
    s = json.dumps({'ambient': {"temperature": currentTemp,
                                "humidity": random.randint(24, 27)}})
    client.publish(topic='hello/world', payload=s)

    # Asynchronously schedule this function to be run again in 5 seconds
    Timer(5, greengrass_simulated_temp_sensor_run, args=[currentTemp]).start()


# Start executing the function above
greengrass_simulated_temp_sensor_run(21)


# This is a dummy handler and will not be invoked
# Instead the code above will be executed in an infinite loop for our example
def function_handler(event, context):
    return
