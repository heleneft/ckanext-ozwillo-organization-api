from hashlib import sha1
import hmac
import requests
import logging
import json
from slugify import slugify

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

import ckan.logic as logic
import ckan.lib.base as base

from pylons import config
from ckan.common import request, _
from ckan.logic.action.create import _group_or_org_create as group_or_org_create
from ckan.logic.action.create import user_create
from ckan.logic.action.delete import _group_or_org_purge
from ckan.lib.plugins import DefaultOrganizationForm

plugin_config_prefix = 'ckanext.ozwillo_organization_api.'

log = logging.getLogger(__name__)

def valid_signature_required(secret_prefix):

    signature_header_name = config.get(plugin_config_prefix + 'signature_header_name',
                                       'X-Hub-Signature')
    api_secret = config.get(plugin_config_prefix + secret_prefix +'_secret', 'secret')

    def decorator(func):
        def wrapper(context, data):
            if signature_header_name in request.headers:
                if request.headers[signature_header_name].startswith('sha1='):
                    algo, received_hmac = request.headers[signature_header_name].rsplit('=')
                    computed_hmac = hmac.new(api_secret, request.body, sha1).hexdigest()
                    if received_hmac.lower() != computed_hmac:
                        log.info('Invalid HMAC')
                        raise logic.NotAuthorized(_('Invalid HMAC'))
                else:
                    log.info('Invalid HMAC algo')
                    raise logic.ValidationError(_('Invalid HMAC algo'))
            else:
                log.info('No HMAC in the header')
                raise logic.NotAuthorized(_("No HMAC in the header"))
            return func(context, data)
        return wrapper
    return decorator


@valid_signature_required(secret_prefix='instantiation')
def create_organization(context, data_dict):
    context['ignore_auth'] = True
    model = context['model']
    session = context['session']

    destruction_secret = config.get(plugin_config_prefix + 'destruction_secret',
                                       'changeme')

    client_id = data_dict.pop('client_id')
    client_secret = data_dict.pop('client_secret')
    instance_id = data_dict.pop('instance_id')

    # re-mapping received dict
    registration_uri = data_dict.pop('instance_registration_uri')
    organization = data_dict['organization']
    user = data_dict['user']
    user_dict = {
        'id': user['id'],
        'name': user['id'].replace('-', ''),
        'email': user['email_address'],
        'password': user['id']
    }
    user_obj = model.User.get(user_dict['name'])

    org_dict = {
        'type': 'organization',
        'name': slugify(organization['name']),
        'id': instance_id,
        'title': organization['name'],
        'user': user_dict['name']
    }

    if not user_obj:
        user_create(context, user_dict)
    context['user'] = user_dict['name']

    try:
        delete_uri = toolkit.url_for(host=request.host,
                                     controller='api', action='action',
                                     logic_function="delete-ozwillo-organization",
                                     ver=context['api_version'],
                                     qualified=True)
        organization_uri = toolkit.url_for(host=request.host,
                                           controller='organization',
                                           action='read',
                                           id=org_dict['name'],
                                           qualified=True)
        default_icon_url = toolkit.url_for(host=request.host,
                                           qualified=True,
                                           controller='home',
                                           action='index') + 'opendata.png'

        group_or_org_create(context, org_dict, is_org=True)

        # setting organization as active explicitely
        group = model.Group.get(org_dict['name'])
        group.state = 'active'
        group.image_url = default_icon_url
        group.save()
        model.repo.new_revision()
        model.GroupExtra(group_id=group.id, key='client_id',
                         value=client_id).save()
        model.GroupExtra(group_id=group.id, key='client_secret',
                         value=client_secret).save()
        session.flush()

        # notify about organization creation
        services = {'services': [{
            'local_id': 'organization',
            'name': 'Open Data',
            'service_uri': organization_uri + '/sso',
            'description': 'Organization ' + org_dict['name'] + ' on CKAN',
            'tos_uri': organization_uri,
            'policy_uri': organization_uri,
            'icon': group.image_url,
            'payment_option': 'FREE',
            'target_audience': ['PUBLIC_BODIES'],
            'contacts': [organization_uri],
            'redirect_uris': [organization_uri + '/callback'],
            'post_logout_redirect_uris': [organization_uri + '/logout'],
            'visible': False}],
            'instance_id': instance_id,
            'destruction_uri': delete_uri,
            'destruction_secret': destruction_secret,
            'needed_scopes': [{
                'scope_id': 'profile',
                'motivation': 'Used to link user to the organization'
            }]
        }
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        requests.post(registration_uri,
                      data=json.dumps(services),
                      auth=(client_id, client_secret),
                      headers=headers
                  )
    except logic.ValidationError, e:
        log.debug('Validation error "%s" occured while creating organization' % e)
        raise

@valid_signature_required(secret_prefix='destruction')
def delete_organization(context, data_dict):
    data_dict['id'] = data_dict.pop('instance_id')
    context['ignore_auth'] = True
    _group_or_org_purge(context, data_dict, is_org=True)


class OrganizationForm(plugins.SingletonPlugin, DefaultOrganizationForm):
    """
    Custom form ignoring 'title' and 'name' organization fields
    """
    plugins.implements(plugins.IGroupForm)

    def is_fallback(self):
        return False

    def group_types(self):
        return ('organization',)

    def group_controller(self):
        return 'organization'

    def form_to_db_schema(self):
        schema = super(OrganizationForm, self).form_to_db_schema()
        del schema['name']
        del schema['title']
        return schema


class ErrorController(base.BaseController):
    def error403(self):
        return base.abort(403, '')


class OzwilloOrganizationApiPlugin(plugins.SingletonPlugin):
    """
    API for OASIS to create and delete an organization
    """
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IRoutes)

    def before_map(self, map):
        # disable organization and members api
        for action in ('member_create', 'member_delete',
                       'organization_member_delete',
                       'organization_member_create',
                       'organization_create',
                       'organization_update',
                       'organization_delete'):
            map.connect('/api/{ver:.*}/action/%s' % action,
                        controller=__name__ + ':ErrorController',
                        action='error403')
        return map

    def after_map(self, map):
        return map

    def update_config(self, config):
        toolkit.add_template_directory(config, 'templates')
        toolkit.add_public_directory(config, 'public')

    def get_actions(self):
        return {
            'create-ozwillo-organization': create_organization,
            'delete-ozwillo-organization': delete_organization
        }

class CreateOrganizationPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.interfaces.IOrganizationController, inherit=True)

    def create(self, entity):
        city = 'Auron' #TO CHANGE TO CITY
        organization_id = entity.id

        base_url_1 = 'https://www.data.gouv.fr/api/1/territory/suggest/?q='
        base_url_2 = 'https://www.data.gouv.fr/api/1/spatial/zone/'
        end_url_2 = '/datasets?dynamic=true'

        try:
            city_response = requests.get(base_url_1 + slugify(city))
            city_json = city_response.json()
            city_name = city_json[0]['title']
            city_id = city_json[0]['id']

            package_data = {'name': slugify(city_name),
                            'private': 'false',
                            'owner_org': organization_id}
            package_id = toolkit.get_action('package_create')({'return_id_only': 'true'}, package_data)

            url = base_url_2 + city_id + end_url_2
            city_datasets = requests.get(url)
            dataset_json = city_datasets.json()
            dataset_dict = {el['title']: el['page'] for el in dataset_json}

            for key, value in dataset_dict.items():
                gouv_resource = {'package_id': package_id,
                                 'url': value,
                                 'name': key}
                toolkit.get_action('resource_create')({}, gouv_resource)

        except Exception as e:
            log.error(e)
            return
