"""
Communications with the Cb Protection server.
"""

from cbapi.protection.models import *
from cbapi.protection.rest_api import CbEnterpriseProtectionAPI
from common import BannedFile


class CbComms(object):

    def __init__(self):

        # TODO load these options from a config.ini file
        self._cbp = CbEnterpriseProtectionAPI(
            url='',
            token='',
            ssl_verify=False
        )

    def pull_banned_files(self):
        """
        Reach out to the Cb Protection server and pull out information
        on each banned file that exists in the environment.
        :return: a list of BannedFiles
        """

        banned_files = self._cbp.select(FileInstance).where("localState:3")
        print(banned_files.__dict__)

        banned_file_rule = self._cbp.select(FileRule).where(
            "fileCatalogId:{}".format(banned_files[0].fileCatalogId))
        print(banned_file_rule.__dict__)

        files = list()
        for fileObject in banned_files:
            sha1 = self._cbp.select(FileCatalog).where(
                "id:{}".format(fileObject.fileCatalogId)).first().sha1
            md5 = self._cbp.select(FileCatalog).where(
                "id:{}".format(fileObject.fileCatalogId)).first().md5

            # construct the banned file object
            this_file = BannedFile()
            this_file.device_os_name = fileObject.computer.osShortName
            this_file.device = fileObject.computer.name
            this_file.path = fileObject.pathName
            this_file.name = fileObject.fileName
            this_file.sha1 = sha1
            this_file.md5 = md5

            files.append(this_file)

        return files






