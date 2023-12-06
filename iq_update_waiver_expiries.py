# Copyright (c) 2011-present Sonatype, Inc. All rights reserved.
# "Sonatype" is a trademark of Sonatype, Inc.

import argparse
import requests
import re
import datetime

APPLICATIONS_CATEGORIES_ENDPOINT = '/api/v2/applicationCategories/application/{}/applicable'
APPLICATIONS_ENDPOINT = '/api/v2/applications'
APPLICABLE_WAIVERS_ENDPOINT = '/api/v2/policyViolations/{}/applicableWaivers'
ORGANIZATIONS_ENDPOINT = '/api/v2/organizations'
POLICY_WAIVERS_ENDPOINT = '/api/v2/policyWaivers/{}/{}'
REPORT_ID_ENDPOINT = '/api/v2/reports/applications/{}'
REPORT_POLICY_VIOLATIONS_PATH = '/policy'
WAIVER_ENDPOINT = '/api/v2/policyWaivers/{}/{}/{}'

http_headers = {'Content-Type': 'application/json;charset=UTF-8', 'Accept': 'application/json, text/plain, */*'}


def __request(server_url, endpoint, username, password):
    response = requests.get(server_url + endpoint, auth=(username, password))
    if response.status_code == 404:
        return None
    elif response.status_code != 200:
        raise ConnectionError(response.reason)
    return response.json()


def __filter_application(server_url, username, password, application, categories):
    """ Returns True if the application has a category that exists in the categories list. """
    if not application['applicationTags']:
        return False

    application_tag_ids = []
    for application_tag in application['applicationTags']:
        application_tag_ids.append(application_tag['tagId'])

    response = __request(server_url, APPLICATIONS_CATEGORIES_ENDPOINT.format(application['publicId']), username,
                         password)

    tag_id_to_name = {}
    for applicable_application_category in response:
        tag_id_to_name[applicable_application_category['id']] = applicable_application_category['name']

    for application_tag_id in application_tag_ids:
        if tag_id_to_name[application_tag_id] in categories:
            return True

    return False


def __get_applications(server_url, username, password, categories):
    """ Calls IQ and gets a listing of all applications available to the given user that match the provided
    categories. """
    response = __request(server_url, APPLICATIONS_ENDPOINT, username, password)
    applications = response['applications']
    result = []
    for application in applications:
        if not categories:
            result.append(application)
        elif __filter_application(server_url, username, password, application, categories):
            result.append(application)

    return result


def __get_organizations(server_url, username, password):
    """ Returns all organizations available to the user. """
    response = __request(server_url, ORGANIZATIONS_ENDPOINT, username, password)
    return response['organizations']


def __get_policy_waivers(server_url, username, password, owner_type, owner_id):
    """ Returns all policy waivers for the given owner type and ID. """
    return __request(server_url, POLICY_WAIVERS_ENDPOINT.format(owner_type, owner_id), username,
                     password)


def __get_applicable_waivers(server_url, username, password, policy_violation_id):
    """ For a given policy violation, return all applicable waivers, both active and expired. """
    response = __request(server_url, APPLICABLE_WAIVERS_ENDPOINT.format(policy_violation_id), username, password)
    waivers = response['activeWaivers']
    waivers.extend(response['expiredWaivers'])

    results = []
    for waiver in waivers:
        results.append({'policyId': waiver['policyId'],
                        'policyViolationId': waiver['policyViolationId'],
                        'policyWaiverId': waiver['policyWaiverId']})

    return results


def __get_policy_violation_report_urls(server_url, username, password, application):
    """ Given an application, return all policy violation report URLs. """
    results = []
    reports = __request(server_url, REPORT_ID_ENDPOINT.format(application['id']), username, password)
    for report in reports:
        report_data_url_path = '/' + report['reportDataUrl']
        if report_data_url_path.endswith('/raw'):
            report_data_url_path = report_data_url_path[:-4]

        results.append(report_data_url_path + REPORT_POLICY_VIOLATIONS_PATH)

    return results


def __get_waived_policy_violations(server_url, username, password, applications):
    """ For each application, find all of its reports, then in each report find all policy violations. If that policy
    violation has been waived, find all applicable waivers. """
    results = []
    for application in applications:
        policy_violations_urls = __get_policy_violation_report_urls(server_url, username, password, application)
        for policy_violations_url in policy_violations_urls:
            policy_violation_report = __request(server_url, policy_violations_url, username, password)
            for component in policy_violation_report['components']:
                for policy_violation in component['violations']:
                    if policy_violation['waived']:
                        results.extend(__get_applicable_waivers(server_url, username, password,
                                                                policy_violation['policyViolationId']))

    return results


def __filter_policy_waivers(waivers, old_date):
    """ Filter policy waivers based on date. If the date is equal to the provided expiration date it will pass the
    filter. """
    if not waivers:
        return []

    results = []
    for waiver in waivers:
        if not old_date:
            if not 'expiryTime' in waiver:
                results.append(waiver)
        else:
            if 'expiryTime' in waiver:
                current_expiry_time = datetime.date.fromisoformat(__parse_waiver_expiry_time(waiver['expiryTime']))
                if current_expiry_time == old_date:
                    results.append(waiver)

    return results


def __parse_waiver_expiry_time(expiry_time):
    """ We only care about day level of granularity so remove hours, minutes, and seconds. """
    return expiry_time.split('T')[0]


def __match_applications(applications, application_regex):
    """ Filter the provided list if the application public ID matches the given regular expression. """
    if not application_regex:
        return applications

    valid_regex = re.compile(application_regex)
    result = []
    for application in applications:
        if valid_regex.match(application['publicId']):
            result.append(application)

    return result


def __match_organizations(organizations, organization_regex):
    """ Filter the provided list of organizations if the organization name matches the given regular expression. """
    if not organization_regex:
        return organizations

    valid_regex = re.compile(organization_regex)
    result = []
    for organization in organizations:
        if valid_regex.match(organization['name']):
            result.append(organization)

    return result


def __parse_old_expiry_date(old_date):
    """ Returns the old expiry date as a datetime object. """
    if not old_date:
        return None

    return datetime.date.fromisoformat(old_date)


def __parse_new_expiry_date(days_from_now):
    """ Return a new datetime object that is a number of days (plus or minus) from today. """
    return datetime.date.today() + datetime.timedelta(days=days_from_now)


def __map_waivers_to_policy_violations(waivers, policy_violations):
    """ Creates a map of waiver IDs to a policy violation. We only need a single policy violation for the waiver
    creation as the policy violation is used for its coordinates and nothing more. """
    waivers_map = {}
    for waiver in waivers:
        waivers_map[waiver['policyWaiverId']] = waiver

    results = {}
    for policy_violation in policy_violations:
        if policy_violation['policyWaiverId'] in waivers_map:
            results[policy_violation['policyWaiverId']] = policy_violation

    return results


def __parse_owner_type(waiver):
    """ Because waiver's have a special owner type for the root organization that the API doesn't accept we need to
    account for that and map it to 'organization'. """
    owner_type = None
    if waiver['scopeOwnerType'] == 'root_organization':
        owner_type = 'organization'
    else:
        owner_type = waiver['scopeOwnerType']
    return owner_type


def __post_waiver(server_url, username, password, waiver, policy_violation, new_date):
    """ Create a new waiver that is identical to the old waiver except it uses the new_date as the expiry time. """
    owner_type = __parse_owner_type(waiver)

    data = {'matcherStrategy': waiver['matcherStrategy'], 'expiryTime': new_date.strftime('%Y-%m-%dT00:00:00.000+0000'),
            'comment': waiver['comment']}

    response = requests.post(
        server_url + WAIVER_ENDPOINT.format(owner_type, waiver['scopeOwnerId'], policy_violation['policyViolationId']),
        json=data, auth=(username, password), headers=http_headers)

    if response.status_code == 400 and response.text:
        print("Attempted to create a duplicate waiver for policy violation {}.".format(
            policy_violation['policyViolationId']))
    elif response.status_code != 204:
        raise ConnectionError(response.reason)

    return response


def __delete_waiver(server_url, username, password, waiver):
    """ Delete the provided waiver. """
    owner_type = __parse_owner_type(waiver)

    response = requests.delete(
        server_url + WAIVER_ENDPOINT.format(owner_type, waiver['scopeOwnerId'], waiver['policyWaiverId']),
        auth=(username, password), headers=http_headers)
    if response.status_code == 404:
        print("Attempted to delete a waiver, {}, that does not exist.".format(waiver['policyWaiverId']))
    elif response.status_code != 204:
        raise ConnectionError(response.reason)

    return response


def __parse_waiver_component_display_name(waiver):
    """ Because the waiver display name could be blank for waivers that are for all components we need to guard
    against that case. """
    if not waiver['displayName']:
        return ''

    return waiver['displayName']['name']


def __aggregate_waivers(server_url, username, password, organizations, applications, old_date):
    """ For each application and organization, get all of their waivers and filter out those that do not match up
    with the provided expiry date. """
    waivers = []
    for organization in organizations:
        waivers.extend(__filter_policy_waivers(
            __get_policy_waivers(server_url, username, password, 'organization', organization['id']), old_date))

    for application in applications:
        waivers.extend(__filter_policy_waivers(
            __get_policy_waivers(server_url, username, password, 'application', application['id']), old_date))

    return waivers


def __update_policy_waiver_expirations(server_url, username, password, organizations, applications, old_date, new_date):
    """ First get all waivers. Then get all waived policy violations. Map the waiver ID to the
    policy violation that it waives. Then delete the old waiver and create a new wavier against the policy violation
    with the new expiry date. """
    waivers = __aggregate_waivers(server_url, username, password, organizations, applications, old_date)

    waived_policy_violations = __get_waived_policy_violations(server_url, username, password, applications)

    waivers_to_policy_violations = __map_waivers_to_policy_violations(waivers, waived_policy_violations)

    # TODO It might be a good idea to dump existing waivers to disk prior to deleting them so there is a back up in
    #  case of failure.
    for waiver in waivers:
        if waiver['policyWaiverId'] in waivers_to_policy_violations:
            print('Deleting waiver {} for policy {} for component "{}".'.format(waiver['policyWaiverId'],
                                                                                waiver['policyId'],
                                                                                __parse_waiver_component_display_name(
                                                                                    waiver)))
            __delete_waiver(server_url, username, password, waiver)
            print(
                'Creating waiver for policy {} for component "{}" with matcher strategy {} and new expiry date {}.'.format(
                    waiver['policyId'], __parse_waiver_component_display_name(waiver), waiver['matcherStrategy'],
                    new_date.strftime('%Y-%m-%dT00:00:00.000+0000')))
            __post_waiver(server_url, username, password, waiver,
                          waivers_to_policy_violations[waiver['policyWaiverId']], new_date)
    print('\n')


def __parse_args():
    parser = argparse.ArgumentParser(
        description='Connects to IQ and updates waivers that have been set to expire on a given date, or never, to a new date.')
    parser.add_argument('-s', dest='server_url',
                        default='http://localhost:8070', help='URL of IQ instance.', required=True)
    parser.add_argument('-u', dest='username', help='IQ user\'s username.', required=True)
    parser.add_argument('-p', dest='password', help='IQ user\'s password.', required=True)
    parser.add_argument('-e', dest='old_expiry_date', nargs="?", default=None, const=None,
                        help='The old expiry date to update. If not assigned it will default to "never" expire. Must be in yyyy-MM-dd format if set. Defaults to None or "never" expire.')
    parser.add_argument('-d', dest='new_expiry_days_from_now', nargs="?", default=30, const=30, type=int,
                        help='The number of days from now to set the new expiry. Defaults to 30 days from today.')
    parser.add_argument('-fa', dest='application_regex',
                        help='A regular expression to be matched against application public ID. Can be used in conjunction with the categoires filter.')
    parser.add_argument('-fo', dest='organization_regex',
                        help='A regular expression to be matched against organization name.')
    parser.add_argument('-c', dest='categories', nargs='+',
                        help='An optional list of application categories to use as a filter for applications.')
    return parser.parse_args()


if __name__ == "__main__":
    args = __parse_args()

    old_expiry_date = __parse_old_expiry_date(args.old_expiry_date)
    new_expiry_date = __parse_new_expiry_date(args.new_expiry_days_from_now)
    filtered_applications = __match_applications(
        __get_applications(args.server_url, args.username, args.password, args.categories), args.application_regex)
    filtered_organizations = __match_organizations(__get_organizations(args.server_url, args.username, args.password),
                                                   args.organization_regex)

    __update_policy_waiver_expirations(args.server_url, args.username, args.password, filtered_organizations,
                                       filtered_applications, old_expiry_date, new_expiry_date)
