from urllib.parse import urljoin, quote
from collections import defaultdict
import json
from copy import copy
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

logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

_pod_variant_default_scheduled = defaultdict(list)


class ErrorSchedulingPod(Exception):
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


def escape_jsonpatch_value(value):
    return value.replace('/', '~1')


def is_pod_dead(label_selector, pod_name):
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


def record_as_default_scheduled(label_selector, pod):
    pod_name = pod['metadata']['name']
    _pod_variant_default_scheduled[label_selector].append(pod_name)


def is_default_scheduled(label_selector, pod):
    pod_name = pod['metadata']['name']

    for pod_name in _pod_variant_default_scheduled[label_selector]:
        if is_pod_dead(label_selector, pod_name):
            _pod_variant_default_scheduled[label_selector].remove(pod_name)

    # We want to clear out stopped / dead pods
    if not _pod_variant_default_scheduled[label_selector]:
        return False

    return True


def clear_default_scheduled(label_selector, pod):
    pod_name = pod['metadata']['name']
    if label_selector in _pod_variant_default_scheduled[label_selector]:
        del _pod_variant_default_scheduled[label_selector]


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


def set_default_scheduler_on_pod(pod):
    pod_name = pod['metadata']['name']
    label_selector = get_pod_selector(pod)
    _log.info('Setting default scheduler on pod {} ({})'.format(
        pod_name, label_selector))

    url = urljoin(API_URL, 'namespaces/{}/pods/{}'.format(NAMESPACE, pod_name))
    headers = {
        'Content-Type': 'application/json-patch+json',
        'Accept': 'application/json',
    }
    scheduler_key = escape_jsonpatch_value('scheduler.alpha.kubernetes.io/name')
    payload = [{
        'op': 'replace',
        'path': '/metadata/annotations/{}'.format(scheduler_key),
        'value': DEFAULT_KUBERNETES_SCHEDULER
    }]

    r = k8_request('patch', url, data=json.dumps(payload), headers=headers)

    if r.status_code != 200:
        raise ErrorSchedulingPod(
            'There was an error setting the default scheduler on '
            'pod {}.'.format(pod_name))

    record_as_default_scheduled(label_selector, pod)


def bind_pod_to_node(pod, node_running_pod):
    pod_name = pod['metadata']['name']
    label_selector = get_pod_selector(pod)
    _log.info('Binding pod {} ({}) to node {}'.format(
        pod_name, label_selector, node_running_pod))

    clear_default_scheduled(label_selector, pod)

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


def process_unscheduled_pods(pods):
    for pod in pods:
        metadata = pod.get('metadata', {})
        annotations = metadata.get('annotations', {})
        pod_scheduler_name = annotations.get('scheduler.alpha.kubernetes.io/name')
        label_selector = get_pod_selector(pod)

        # We only schedule unschedule pods that are set to use this scheduler.
        if pod_scheduler_name == OUR_SCHEDULER_NAME:
            node_running_pod = get_node_running_pod(pod)
            if not node_running_pod:
                if is_default_scheduled(label_selector, pod):
                    # We wait for the default-scheduled pod to come online.
                    # The default scheduler won't kick in instantly, so we
                    # need to wait for it to schedule the previous pod variant.
                    return

                # If the pod isn't already running somewhere, then we tell the pod
                # to instead use the default scheduler.
                _log.info(
                    'No node currently running pod of form {}. Handing off to '
                    'the default scheduler.'.format(label_selector))
                set_default_scheduler_on_pod(pod)
                # After handing off to the default scheduler, we need to
                # regenerate the list of unscheduled posts, so we return here.
                return

            bind_pod_to_node(pod, node_running_pod)


def run_loop():
    while True:
        unscheduled_pods = get_unscheduled_pods()
        process_unscheduled_pods(unscheduled_pods)


if __name__ == '__main__':
    run_loop()
