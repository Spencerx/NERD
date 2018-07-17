#!/bin/sh
# Clear contents of all nerd-worker-* queues in RabbitMQ.
# Must be run as root.

queue_list=$(rabbitmqadmin list queues name -f tsv | grep "^nerd-worker-")

for q in $queue_list
do
  rabbitmqadmin purge queue name=$q
done
