`sticky-node-scheduler` is a custom [Kubernetes](http://kubernetes.io/)
scheduler that schedules all variants of a given pod on the same node.

If a pod variant isn't running on any nodes, we pick a node to schedule on to
based on which node is running the least amount of our sticky-scheduled pods.
If any varients of a pod *are* running, then we place all copies of the pod
on the same node.

If you're using e.g. EBS volumes, which can only be attached to a single node
at a time, and need seamless updates of your stateful Deployments, this might
be useful to you.

This scheduler only works with Kubernetes >= 1.6, which support custom
schedulers as a beta feature.

NOTE: This is **not** ready for production usage.


How to use
----------

First, deploy the scheduler into your cluster:

    $ kubectl apply -f deployment.yml

Then, for each Deployment or ReplicationController you want to schedule
using this scheduler, add:

    schedulerName: stickToExistingNodeScheduler

to the pod spec.  For instance:

    apiVersion: extensions/v1beta1
    kind: Deployment
    metadata:
      name: my-stateful-service
    spec:
      replicas: 2
      template:
        metadata:
          labels:
            app: my-stateful-service
        spec:
          schedulerName: stickToExistingNodeScheduler
          containers:
            - name: my-stateful-service
              image: stateful-service-image


The scheduler identifies 'variants' of your pods based on the
`metadata.labels` entry in your pod template.


Options
-------

The `NODE_FILTER_QUERY` environment variable controls which nodes are
selected for scheduling.  By default, it is set to
`labelSelector=kubernetes.io/role=node`, which will filter only nodes (e.g.
we won't schedule on to your master nodes).

The `POLL_FREQUENCY` environment variable controls how often we poll the
Kubernetes API for changes, per second.  The default is `0.5`.


License
-------

Copyright (c) 2016, 2017 Shotwell Labs, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
