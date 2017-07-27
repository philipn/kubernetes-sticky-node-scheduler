import os
from urllib.parse import urljoin, quote
from collections import defaultdict
import json
from copy import copy, deepcopy
import logging

import requests


API_URL = 'https://kubernetes/api/v1/'
OUR_SCHEDULER_NAME = 'stickToExistingNodeScheduler'
DEFAULT_KUBERNETES_SCHEDULER = 'default-scheduler'
NAMESPACE = 'default'

TOKEN_LOCATION = '/var/run/secrets/kubernetes.io/serviceaccount/token'
CA_BUNDLE_LOCATION = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'

logging.basicConfig(level=logging.INFO)
_log = logging.getLogger(__name__)

NODE_FILTER_QUERY = os.environ.get('NODE_FILTER_QUERY', '')

logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

_nodes_scheduled_to = defaultdict(list)
_nodes_to_skip = defaultdict(list)


class ErrorSchedulingPod(Exception):
    pass


class ErrorDeletingPod(Exception):
    pass


class ErrorCreatingPod(Exception):
    pass


class NoValidNodesToScheduleTo(Exception):
    pass


def k8_token_content():
    with open(TOKEN_LOCATION) as f:
        return f.read()


def k8_request(method, url, headers=None, **kwargs):
    if headers is None:
        headers = {}
    f = getattr(requests, method)
    our_headers = copy(headers)
    our_headers['Authorization'] = 'Bearer {}'.format(k8_token_content())

    return f(url, headers=our_headers, verify=CA_BUNDLE_LOCATION, **kwargs)


def get_unscheduled_pods():
    pending_pods_url = urljoin(API_URL, 'pods?fieldSelector=spec.nodeName=')
    r = k8_request('get', pending_pods_url)
    pending_pods_info = r.json()
    return pending_pods_info.get('items', [])


def get_failed_pods():
    failed_pods = urljoin(API_URL, 'pods?fieldSelector=status.phase=Failed')
    r = k8_request('get', failed_pods)
    pending_pods_info = r.json()
    return pending_pods_info.get('items', [])


def escape_jsonpatch_value(value):
    return value.replace('/', '~1')


def _is_pod_running_or_pending(label_selector, pod_name):
    url = urljoin(API_URL, 'pods?labelSelector={}'.format(
            quote(label_selector)))
    r = k8_request('get', url)
    pods_for_selector = r.json()

    for pod in pods_for_selector.get('items', []):
        if pod['metadata']['name'] != pod_name:
            continue
        status = pod.get('status', {}).get('phase')
        if status.lower() == 'running' or status.lower() == 'pending':
            return True
        else:
            return False

    return True


def get_pod_selector(pod):
    """
    Returns:
        The string representing the labelSelector to select pods of this
        general type.
    """
    labels = pod['metadata'].get('labels', {})
    # We don't use the 'pod-template-hash' label because we want to schedule
    # our new pods onto the node they're currently running on, even if the
    # pod template has been updated (in our case, that's the point!)
    if 'pod-template-hash' in labels:
        del labels['pod-template-hash']

    selector = []
    for k in sorted(labels.keys()):
        selector.append('{}={}'.format(k, labels[k]))
    return ','.join(selector)


def get_nodes():
    """
    Returns:
        A list of node name strings.
    """
    url = urljoin(API_URL, 'nodes?{}'.format(NODE_FILTER_QUERY))
    r = k8_request('get', url)
    result = r.json()
    nodes = result['items']

    return [n['metadata']['name'] for n in nodes]


def get_node_running_pod(pod):
    nodes = set()

    label_selector = get_pod_selector(pod)
    url = urljoin(API_URL, 'pods?labelSelector={}'.format(
            quote(label_selector)))
    r = k8_request('get', url)
    pods_for_selector = r.json()

    for pod in pods_for_selector.get('items', []):
        node_name = pod['spec'].get('nodeName')
        if not node_name:
            continue
        status = pod.get('status', {}).get('phase')
        if status.lower() != 'running' and status.lower() != 'pending':
            continue
        nodes.add(node_name)

    assert len(nodes) <= 1, "Pod should only be running on one or less node"
    return nodes.pop() if nodes else None


def create_pod_definition(pod):
    """
    Args:
        pod: A dictionary describing a pod.

    Returns:
        A pod definiton suitable for a create request from the API.
    """
    pod = deepcopy(pod)

    # Remove elements that are not needed in the pod creation
    # definition, or elements that aren't allowed in the pod
    # creation definition.
    pod.pop('status', None)
    if 'annotations' in pod['metadata']:
        pod['metadata']['annotations'].pop('kubernetes.io/created-by', None)
    #pod['metadata'].pop('name', None)
    #pod['metadata'].pop('generateName', None)
    pod['metadata'].pop('creationTimestamp', None)
    pod['metadata'].pop('generateTime', None)
    #pod['metadata'].pop('ownerReferences', None)
    pod['metadata'].pop('resourceVersion', None)
    pod['metadata'].pop('selfLink', None)
    pod['metadata'].pop('uid', None)

    return pod


def set_default_scheduler_on_pod(pod):
    # It's currently not possible to change the scheduler on an existing
    # pod -- see https://github.com/kubernetes/kubernetes/issues/24913
    # Because of this, we delete the pod and re-create it with the default
    # scheduler set.
    label_selector = get_pod_selector(pod)

    # We first create the new pod, because otherwise a RC/Deployment
    # may re-create the deleted pod before we can create it.
    new_pod = create_pod_definition(pod)
    del new_pod['spec']['schedulerName']
    new_pod['metadata']['name'] += '-rescheduled'
    create_pod(new_pod)
    record_as_default_scheduled(label_selector, new_pod)
    delete_pod(pod)


def create_pod(pod):
    pod_name = pod['metadata']['name']
    label_selector = get_pod_selector(pod)
    _log.info('Creating pod {} ({})'.format(
        pod_name, label_selector))

    url = urljoin(API_URL, 'namespaces/{}/pods'.format(
        NAMESPACE))

    r = k8_request('post', url, json=pod)
    if r.status_code != 201:
        raise ErrorCreatingPod(
            'There was an error creating pod {}.'.format(
                pod_name))


def delete_pod(pod):
    pod_name = pod['metadata']['name']
    label_selector = get_pod_selector(pod)
    _log.info('Deleting pod {} ({})'.format(
        pod_name, label_selector))

    url = urljoin(API_URL, 'namespaces/{}/pods/{}'.format(
        NAMESPACE, pod_name))

    payload = {
        'apiVersion': 'v1',
        'gracePeriodSeconds': 0,
    }

    r = k8_request('delete', url, json=payload)
    if r.status_code != 200:
        raise ErrorDeletingPod(
            'There was an error deleting pod {}.'.format(
                pod_name))


def bind_pod_to_node(pod, node_running_pod):
    pod_name = pod['metadata']['name']
    label_selector = get_pod_selector(pod)
    _log.info('Binding pod {} ({}) to node {}'.format(
        pod_name, label_selector, node_running_pod))

    url = urljoin(API_URL, 'namespaces/{}/pods/{}/binding'.format(
        NAMESPACE, pod_name))

    payload = {
        'apiVersion': 'v1',
        'kind': 'Binding',
        'metadata': {
          'name': pod_name,
        },
        'target': {
          'apiVersion': 'v1',
          'kind': 'Node',
          'name': node_running_pod,
        } 
    }

    r = k8_request('post', url, json=payload)
    if r.status_code != 201:
        raise ErrorSchedulingPod(
            'There was an error scheduling pod {} on node {}.'.format(
                pod_name, node_running_pod))


def pick_node_to_schedule_to(pod):
    label_selector = get_pod_selector(pod)
    nodes = get_nodes()

    # Remove nodes that are now gone
    old_nodes = set([n for n in _nodes_scheduled_to])
    new_nodes = set(nodes)

    for node in (new_nodes - old_nodes):
        # Add new nodes
        _nodes_scheduled_to[node] = []

    for node in (old_nodes - new_nodes):
        # Delete nodes that are gone
        del _nodes_scheduled_to[node]

    nodes_to_skip = _nodes_to_skip[label_selector]

    # Pick a node with the smallest number of our pods
    # scheduled to it.
    nodes = copy(_nodes_scheduled_to)
    for node in nodes_to_skip:
        if node in nodes:
            del nodes[node]
    nodes = list(nodes.items())
    nodes.sort(key=lambda x: len(_nodes_scheduled_to[x[0]]))

    if not nodes:
        raise NoValidNodesToScheduleTo('No more valid nodes to schedule to.')

    return nodes[0][0]


def mark_pod_as_scheduled(pod, node_name):
    label_selector = get_pod_selector(pod)
    _nodes_scheduled_to[node_name].append(label_selector)


def unmark_pod_as_scheduled(pod, node_name):
    label_selector = get_pod_selector(pod)
    if label_selector in _nodes_scheduled_to[node_name]:
        _nodes_scheduled_to[node_name].remove(label_selector)


def process_unscheduled_pods(pods):
    for pod in pods:
        spec = pod.get('spec', {})
        pod_scheduler_name = spec.get('schedulerName')
        label_selector = get_pod_selector(pod)

        # We only schedule pods that are set to use this scheduler.
        if pod_scheduler_name == OUR_SCHEDULER_NAME:
            node_running_pod = get_node_running_pod(pod)

            if node_running_pod:
                node_to_schedule_to = node_running_pod
            else:
                # If the pod isn't already running somewhere, then we pick a
                # node to schedule the pod to.
                try:
                    node_to_schedule_to = pick_node_to_schedule_to(pod)
                except NoValidNodesToScheduleTo:
                    # We will re-try the scheduling again in the parent loop,
                    # but for now we skip it.
                    _log.info(
                        'Skipping scheduling pod of form {} for now.'.format(
                            label_selector))
                    # We clear out the tainted nodes to avoid the scheduler
                    # getting stuck -- we want to re-try previously
                    # failed nodes, now.
                    if label_selector in _nodes_to_skip:
                        del _nodes_to_skip[label_selector]

                    return

                _log.info(
                    'No node currently running pod of form {}. Scheduling it to '
                    'node {}'.format(label_selector, node_to_schedule_to))

            try:
                bind_pod_to_node(pod, node_to_schedule_to)
            except ErrorSchedulingPod:
                if not node_running_pod:
                    # We want to now taint the node we attempted to schedule
                    # on to, so that we will rotate over to a new node
                    # when we try and schedule again.
                    _nodes_to_skip[label_selector].append(node_to_schedule_to)
            else:
                mark_pod_as_scheduled(pod, node_to_schedule_to)
                # Because we were able to schedule the pod, let's clear out the
                # nodes to skip on this label selector.  This will allow us to
                # try nodes that may now be schedulable next time we.
                if not node_running_pod:
                    if _nodes_to_skip[label_selector]:
                        del _nodes_to_skip[label_selector]


def process_failed_pods(pods):
    for pod in pods:
        spec = pod.get('spec', {})
        pod_scheduler_name = spec.get('schedulerName')
        label_selector = get_pod_selector(pod)

        # We only deal with pods that are set to use this scheduler.
        if pod_scheduler_name != OUR_SCHEDULER_NAME:
            continue

        status = pod.get('status')
        _log.error(
            'Pod of type {} failed. Deleting pod and hoping it will '
            're-spawn correctly. Full pod status:\n{}'.format(label_selector, status))

        # Delete the failed pod.  Hopefully it's wired up to a replication
        # controller that will re-spawn it or something.
        delete_pod(pod)

        node_name = pod.get('spec', {}).get('nodeName')
        unmark_pod_as_scheduled(pod, node_name)


def run_loop():
    while True:
        unscheduled_pods = get_unscheduled_pods()
        process_unscheduled_pods(unscheduled_pods)
        failed_pods = get_failed_pods()
        process_failed_pods(failed_pods)


if __name__ == '__main__':
    run_loop()
