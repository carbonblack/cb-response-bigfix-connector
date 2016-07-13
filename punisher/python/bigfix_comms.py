
import requests
import os
import json
from common import BannedFile


class BigfixComms(object):

    def __init__(self):

        # TODO read in fixlet_template
        self._fixlet_template_path = 'xml_templates/fixlet_template.xml'
        self._fixlet_template_string = """"""

    # TODO update these commands to the new syntax provided by the IBM team
    @staticmethod
    def _build_commands(banned_file_list):
        """
        Private function that is able to build the command syntax
        for later insertion into a fixlet template.
        :param banned_file_list: List of banned file objects
        :return: a dictionary containing relevance and
                 actionscript commands for a template
        """
        relevance_command = ""
        actionscript_command = ""

        for banned_file in banned_file_list:
            # right now we focus on windows machines only:
            # print(fileObject)
            if 'Windows' not in banned_file.device_os_name:
                continue

            # else we build out the relevance commands for finding the file
            if relevance_command != "":
                relevance_command += " OR "
            relevance_command += """
                (exists file "{0}" whose
                    (md5 of it as lowercase = "{1}" as lowercase)
                        of folders "{2}")
                """.format(
                    banned_file.name,
                    banned_file.md5,
                    banned_file.path
                )

            # build the actionscript delete statements
            # TODO use something other than os.path.join, need something that
            # TODO   will work on any platform, os.path.join only works on the
            # TODO   platform it is executed on.
            actionscript_command += """
                if {{(exists file "{0}" whose
                    (md5 of it as lowercase = "{1}" as lowercase)
                        of folders "{2}")}}
                        delete "{3}"
                """.format(banned_file.name,
                           banned_file.md5,
                           banned_file.path,
                           os.path.join(banned_file.path, banned_file.name))

        return {'relevance_command': relevance_command,
                'actionscript_command': actionscript_command}

    def update_removal_fixlets(self, banned_files_list):
        """
        This function will create / update fixlets on the BigFix server
        as to keep them up to date with the current state of banned files
        currently in existence within the network.
        :param banned_files_list: list of banned file objects
        """

        # TODO process more than just a single banned file..
        # TODO remove the hardcoded timestamps, insert current time
        search_cmd = self._build_commands(banned_files_list)
        print(search_cmd)
        fixlet_xml = self._fixlet_template_string.format(
            banned_files_list[0]['md5'],  # TODO ahh what a hack.. fix this.
            search_cmd['relevance_command'],
            "2016-06-15",
            "Fri, 01 Jul 2016 18:56:10 +0000",
            search_cmd['actionscript_command'])


    # TODO take the code below and use it to actually pull and send fixlets
    # TODO      to/from the bigfix server.

        # TODO pull these items from a config.ini file
        # bigfix_api_url = 'bigfixcb.dnsalias.com:52311'
        # bigfix_api_username = 'bigfix'
        # bigfix_api_password = 'bigfix'
        # bigfix_auth = (bigfix_api_username, bigfix_api_password)
        #
        # # see if we already have a fixlet of this nature.
        # query_string = 'ids of bes fixlets whose (name of site of it = "Carbon Black"'\
        #                'AND name of it as string as lowercase contains "{0}" as lowercase)'.format(
        #                 file_loc_data[0]['md5'])  #oh that hack again.. fix here too.
        #
        # url = 'https://{0}/api/query'.format(bigfix_api_url)
        # req_result = requests.get(url, auth=bigfix_auth, verify=False,
        #                           params={'relevance': query_string, 'output': 'json'},
        #                           headers={"Accept-Encoding": "gzip"})
        #
        # print(json.dumps(req_result.__dict__.keys()))
        # print(req_result.request.headers)
        # print(req_result.content)
        #
        # # if no existing fixlet found, just make a new one
        # result_json = json.loads(req_result.content)
        # if len(result_json["result"]) == 0:
        #     url = 'https://{0}/api/fixlet/custom/Carbon%20Black/'.format(bigfix_api_url)
        #     put_result = requests.put(url, auth=bigfix_auth, verify=False,
        #                               data=fixlet_xml)
        #     print(put_result)



