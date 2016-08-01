`sticky-node-scheduler` is a custom [Kubernetes](http://kubernetes.io/)
scheduler that schedules all variants a given pod on the same node.

If a pod variant isn't running on any nodes, we use the default Kubernetes
scheduler to schedule the pod.  If any varients of a pod *are* running, then
we place copies of the pod on the same node.

If you're using e.g. EBS volumes and need seamless updates of your stateful
Deployments, this might be useful to you.

NOTE: This is **not** ready for production usage.


How to use
----------

First, deploy the scheduler into your cluster:

    $ kubectl apply -f deployment.yml

Then, for each Deployment or ReplicationController you want to schedule
using this scheduler, add:

    annotations:
        scheduler.alpha.kubernetes.io/name: stickToExistingNodeScheduler

to the template metdata.  For instance:

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
          annotations:
            scheduler.alpha.kubernetes.io/name: stickToExistingNodeScheduler
        spec:
          containers:
            - name: my-stateful-service
              image: stateful-service-image


The scheduler identifies 'variants' of your pods based on the
`metadata.labels` entry in your pod template.


License
-------

Copyright (c) 2016 Shotwell Labs, Inc.

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
