
#blog trigger encryption
#version 1.1
import logging
import azure.functions as func
import gnupg
import gnupg._parsers
gnupg._parsers.Verify.TRUST_LEVELS["ENCRYPTION_COMPLIANCE_MODE"] = 23
#from dowloadfunc import Azuredownload
import os
from azure.storage.blob import BlobServiceClient, BlobClient
from azure.storage.blob import ContentSettings, ContainerClient

My_string = "DefaultEndpointsProtocol=https;AccountName=sftputility;AccountKey=LCbBIUvGJJuiRbgiHlL4G9trjsOVLM/db2K2XtTGiFhfD+W9pbXAv8sEI6CU5s2/ChDo7BIL6rIH+AStJa1+Vg==;EndpointSuffix=core.windows.net"
#My_string = "DefaultEndpointsProtocol=https;AccountName=208678d1musea2st001v2;AccountKey=FJBUv87UgJeOMsr4BjQbeOH0x4CeStJCrqmIetpUIUSsfojABiv+Pk1fDzTOyQtDB6tJp9PZhPCDi5AQx+IZZw==;EndpointSuffix=core.windows.net"
# Replace with blob container
My_container = "report-upload"
#My_container = "report"
def main(myblob: func.InputStream, outputBlob1: func.Out[str],outputBlob2: func.Out[str],outputBlob3: func.Out[str],outputBlob4: func.Out[str]):
    blob_service_client =  BlobServiceClient.from_connection_string(My_string)
    my_container = blob_service_client.get_container_client(My_container)
    
    logging.info(f"Blob trigger executed!")
    logging.info(f"Blob Name: {myblob.name} ")
    #logging.info(f"Full Blob URI: {myblob.uri}")
    gpg = gnupg.GPG(homedir='/home/.config/python-gnupg')
    #gpg = gnupg.GPG()    
    script_dir = os.path.dirname(__file__)
    with open(os.path.join(script_dir, 'DTE_public_key.asc')) as f1:
        key_data_DTE = f1.read()        
    with open(os.path.join(script_dir, 'NG_public_key.asc')) as f2:
        key_data_NG = f2.read()
    with open(os.path.join(script_dir, 'SMUD_public_key.asc')) as f3:
        key_data_SMUD = f3.read()
    with open(os.path.join(script_dir, 'XCEL_public_key.asc')) as f4:
        key_data_XCEL = f4.read()
        
    blob_process = my_container.list_blobs()
   # blob_process = my_container.list_blobs(name_starts_with="Unencrypted-Reports/")    
    for blob in blob_process:
        name=str(blob.name)
        if name.startswith('DTE'):
            logging.info(f"Import DTE key...!")
            import_result = gpg.import_keys(key_data_DTE)
            key=import_result.results[0]
            data1 = my_container.get_blob_client(blob).download_blob().readall()
            encrypted=gpg.encrypt(data1, key['fingerprint'], always_trust=True)   
            output = str(encrypted)
            outputBlob1.set(output)
        elif name.startswith('XCEL'):
            logging.info(f"Import XCEL key...!")
            import_result = gpg.import_keys(key_data_XCEL)
            key=import_result.results[0]
            data2 = my_container.get_blob_client(blob).download_blob().readall() 
            encrypted=gpg.encrypt(data2, key['fingerprint'], always_trust=True)   
            output = str(encrypted)
            outputBlob2.set(output)
        elif name.startswith('SMUD'):
            logging.info(f"Import SMUD key...!")
            import_result = gpg.import_keys(key_data_SMUD)
            key=import_result.results[0]
            data3 = my_container.get_blob_client(blob).download_blob().readall() 
            encrypted=gpg.encrypt(data3, key['fingerprint'], always_trust=True)   
            output = str(encrypted)
            outputBlob3.set(output)
        elif name.startswith('NationalGrid'):
            logging.info(f"Import NationalGid key...!")
            import_result = gpg.import_keys(key_data_NG)
            key=import_result.results[0]            
            data4 = my_container.get_blob_client(blob).download_blob().readall() 
            encrypted=gpg.encrypt(data4, key['fingerprint'], always_trust=True)   
            output = str(encrypted)
            outputBlob4.set(output)            
        else:
            logging.info(" encrypted ust only for report format")
    de_blobs = my_container.list_blobs()
    for blob in de_blobs:
        logging.info(f"Delete all files...!")
        my_container.delete_blobs(blob)