import fastapi
import uvicorn

import asyncio # pylint: disable=import-error
from os import path, pardir, getenv
from signal import SIGTERM
from fastapi import FastAPI, Request, Body, Response, status  # pylint: disable=import-error
from starlette.background import BackgroundTasks as StarletteBackgroundTasks
from fastapi.responses import JSONResponse
from logging import getLogger, config
from acs_request import get_acs_alert, get_rhacs_health,get_policy
from pydantic import BaseModel, SecretStr, ValidationError, WrapValidator, Extra, Field, field_serializer
from pydantic_core import from_json
from aiofiles import open as async_open, os as aiofiles_os
from typing import Any, Optional, AsyncGenerator, Any
from config import settings
from typing_extensions import Annotated
from uuid import uuid4, UUID


    
class ACSViolations(BaseModel):
    message: str

class ACSImageDetails(BaseModel):
    registry: str | None
    remote: str | None
    fullName: str | None

class ACSImage(BaseModel):
    id: str | None = None
    name: ACSImageDetails

class ACSContainer(BaseModel):
    name: str
    image: ACSImage
    notPullable: str | None
    isClusterLocal: str | None

class ACSDeployment(BaseModel):
    '''Affected RHACS Deployment as received from Vulnerability Data'''
    id: str
    name: str
    type: str | None
    namespace: str
    namespaceId: str
    labels: dict | None = None
    clusterId: str
    clusterName: str
    containers: list[ACSContainer]
    annotations: dict | None = None
    inactive: str | None

class ACSPolicy(BaseModel):
    '''Policy Information for Policy generating this Violation'''
    id: str
    name: str
    categories: Optional[str] = None
    lifecycleStages: Optional[list] = None
    severity: Optional[str] = None
    notifiers: Optional[list] = None
    lastUpdated: Optional[str] = None
    SORTName: Optional[str] = None
    SORTLifecycleStage: Optional[str] = None
    policyVersion: Optional[str] = None
    policySections: Optional[dict] = None
    description: Optional[str] = None
    rationale: Optional[str] = None
    remediation: Optional[str] = None
    disabled: bool
    eventSource: Optional[str] = None
    exclusions: Optional[list] = None
    scope: Optional[list] = None
    categories: Optional[list] = None
    severity: Optional[str] = None
    enforcementActions: Optional[list] = None
    mitreAttackVectors: Optional[str] = None
    criteriaLocked: Optional[str] = None
    mitreVectorsLocked: Optional[str] = None
    isDefault: Optional[bool] = None

class ACSPolicyList(BaseModel):
    '''List of Policies'''
    policies: list[ACSPolicy]
    
class ACSAlert(BaseModel, extra=Extra.allow):  # pylint: disable=too-few-public-methods
    '''Class For Alert Information from RHACS'''
    id: str
    policy: ACSPolicy | None
    clusterId: str
    clusterName: str
    namespace: str
    namespaceId: str
    deployment: ACSDeployment
    resource: list | None
    violations: list[ACSViolations]
    time: str
    firstOccurred: str
    lifecycleStage: str | None
    resolvedAt: str | None
    state: str | None
    snoozeTill: str | None
    enforcement: dict | None = None

class ACSEndpoint(BaseModel):
    '''ACS Endpoint Information'''
    internal_id: UUID = Field(default_factory=uuid4)
    endpoint_name: str
    endpoint_url: str
    endpoint_token_env_variable_name: str
    endpoint_token: SecretStr = "Empty"
    verify_endpoint_ssl: bool = False
    healthy: bool = False
    processed: bool = False
    initialized:bool = True
    endpoint_url_description: str = "ACS API endpoint for the application to make request to"
    endpoint_token_env_variable_name_description:str = "Environment Variable to retrieve the Token for this cluster"
    policies: ACSPolicyList = ACSPolicyList(policies=[])
    
class ACSEndpointList(BaseModel):
    '''ACS Endpoint List'''
    endpoints: list[ACSEndpoint]
    
    @classmethod
    def endpoint_count(cls):
        return len(cls.endpoints)
    
class ParsedMemory():
    """Class Container that contains parsed data in Memory at the cluster level"""
    #If we have at least one healthy ACS Endpoint then class can be initialized
    _initialized = False
    #if at least one healthy endpoint is fully processed, and there are no unprocessed endpoints then we can shutdown class/program
    _shutdown = False
    #To help maintain the state of the class, we acquire a lock to read and write to the class
    _lock = asyncio.Lock()
    endpoint_list: ACSEndpointList = ACSEndpointList(endpoints=[])

    @classmethod
    async def append_endpoint_policies(cls,endpoint_uuid,ACSPolicyList:ACSPolicyList) -> bool:
        """
        Append a retrieved list of policies to the endpoint we obtained it from
        """
        async with cls._lock:
            try:
                endpoint = [ endpoint for endpoint in cls.endpoint_list.endpoints if endpoint.internal_id == endpoint_uuid ][0]
                if endpoint is not None:
                    endpoint.policies = ACSPolicyList
                    logger.info(f"Policy Data for Endpoint {endpoint.endpoint_name} appended to the list of ACS endpoints")
                else:
                    logger.error(f"Endpoint {endpoint_uuid} not found in the list of ACS endpoints")
                    return False
            except Exception as e:
                logger.error(f"Endpoint {endpoint_uuid} not found in the list of ACS endpoints")
                logger.error(f"Error: {e}")
                return False

    @classmethod
    async def get_endpoint_count(cls) -> int:
        """
        Get the count of Endpoints
        """
        async with cls._lock:
            return len(cls.endpoint_list.endpoints)
        
    @classmethod
    async def check_are_all_endpoints_unhealthy(cls) -> bool:
        """
        Check if there are no healthy endpoints
        """
        async with cls._lock:
            for endpoint in cls.endpoint_list.endpoints:
                if endpoint.healthy:
                    return False
            return True
                
    @classmethod
    async def append_endpoint(cls,ACS_Endpoint:ACSEndpoint) -> bool:
        """
        Append Endpoint to the List
        """
        async with cls._lock:
            try:
                if ACS_Endpoint.healthy:
                    cls.endpoint_list.endpoints.append(ACS_Endpoint)
                    ACS_Endpoint.initialized = True
                    logger.info(f"Endpoint {ACS_Endpoint.endpoint_name} healthy and appended to the list of ACS endpoints to be polled")
            except Exception as e:
                logger.error(f"Error appending Endpoint {ACS_Endpoint.endpoint_name} to the list")
                logger.error(f"Error: {e}")
                return False
        return True
    
    @classmethod
    async def get_healthy_endpoints(cls) -> ACSEndpointList:
        """
        Get the list of Healthy Endpoints
        """
        async with cls._lock:
            return cls.endpoint_list           
    
    @classmethod
    async def check_all_healthy_endpoints_processed(cls) -> bool:
        """
        Check if all Healthy Endpoints have been processed
        """
        async with cls._lock:
            for endpoint in cls.endpoint_list.endpoints:
                if endpoint.healthy and not endpoint.processed:
                    return False
            return True
               
    @classmethod
    async def get_endpoint_names(cls) -> list[str]:
        """
        Get the list of Endpoint Names
        """
        async with cls._lock:
            return [endpoint.endpoint_name for endpoint in cls.endpoint_list.endpoints]
    
    @classmethod
    async def check_endpoint_valid_healthy(cls,ACS_Endpoint:ACSEndpoint):
        """
        Check if the Endpoint is Healthy and Ready
        """
        
        logger.info(f"Checking Health of Endpoint {ACS_Endpoint.endpoint_name}")
        if not ACS_Endpoint.initialized:
            try:
                token=getenv(ACS_Endpoint.endpoint_token_env_variable_name)
            except:
                logger.error(f"Error reading token from environment variable {ACS_Endpoint.endpoint_token_env_variable_name} for Endpoint {ACS_Endpoint.endpoint_name}")
                return
            ACS_Endpoint.endpoint_token = token
            ACS_Endpoint.initialized = True
                               
        count = settings.health_check_retry_count
        for i in range(count):  
            headers={"Authorization": f"Bearer {ACS_Endpoint.endpoint_token}",
                    "Content-Type": "application/json"}
            try:
                response_dict = await get_rhacs_health(ACS_Endpoint.endpoint_url,ACS_Endpoint.verify_endpoint_ssl,headers)
                if response_dict["response_object"].status_code == 200:
                    logger.info(f"ACS API Connection Successful for Endpoint {ACS_Endpoint.endpoint_name} ")
                    ACS_Endpoint.healthy = True
                else:
                    logger.error(f"ACS API Connection Failed for Endpoint {ACS_Endpoint.endpoint_name} ")
            except Exception as e:
                logger.error(f"ACS API Connection Failed for Endpoint {ACS_Endpoint.endpoint_name} ")
                logger.error(f"Error: {e}")
            finally:
                if ACS_Endpoint.healthy:
                    await cls.append_endpoint(ACS_Endpoint)                   
                    break
                else:
                    if i < count:
                        logger.info(f"Retrying Health Check for Endpoint {ACS_Endpoint.endpoint_name} in {settings.health_check_retry_delay} seconds")
                        await asyncio.sleep(settings.health_check_retry_delay)
                    else:
                        logger.error(f"Health Check Failed for Endpoint {ACS_Endpoint.endpoint_name}")
                        logger.info("We will not be able to poll this endpoint for data")
                        return
                    

# ------------------------------------------------------------------------------------------------
# App Init and Global Variables
# ------------------------------------------------------------------------------------------------
# Logging
log_file_path = path.join(path.dirname(path.abspath(__file__)), 'logging.conf')
config.fileConfig(log_file_path, disable_existing_loggers=False)
logger = getLogger("logger_root")



async def read_parse_acs_endpoints(endpoint_file) -> ACSEndpointList:
    """
    Get the list of ACS Endpoints to poll
    """
        
    logger.info("Reading Endpoint List")
    logger.debug(f"Check that endpoint list file - ({endpoint_file}) is available")
    try:
        await aiofiles_os.stat(str(endpoint_file))
    except OSError as e:
        logger.error(f"Error reading endpoint list file - ({endpoint_file})")
        logger.error(f"Error: {e}")
        logger.info("Exiting")
        return
    except ValueError as e:
        # Non-encodable path
        logger.error(f"Error reading endpoint list file - ({endpoint_file})")
        logger.error(f"Error: {e}")
        logger.info("Exiting")
        return
    
    async with async_open(endpoint_file, mode='r') as filehandle:
        contents = await filehandle.read()
        
    # Verify the JSON        
    try:
        result_endpoint_list=ACSEndpointList.model_validate_json(contents)
    except ValidationError as e:
        logger.error(f"Error: {e}")
        logger.info("Ccontent from file is not valid json for ACSEndpointList")
            
    return result_endpoint_list

async def get_endpoint_policies(ACSEndpoint: ACSEndpoint) -> ACSPolicyList:
    """
    Get the list of Policies for the ACS Endpoints
    """
    
    logger.info("Getting Policies for ACS Endpoints")
    policies = ACSPolicyList(policies=[])
    
    headers={"Authorization": f"Bearer {ACSEndpoint.endpoint_token}",
             "Content-Type": "application/json"}
    response_dict = await get_policy(ACSEndpoint.endpoint_url,ACSEndpoint.verify_endpoint_ssl,headers)
        
    if "error_object" in response_dict and response_dict["error_object"] is not None:
        logger.error(f"Policy Data Not Retrieved for Endpoint {ACSEndpoint.endpoint_name}")
        logger.error(f"Error: {response_dict['error_object']}")
        return
        
    if response_dict["response_object"].status_code == 200:
        logger.info(f"Policy Data Retrieved for Endpoint {ACSEndpoint.endpoint_name}")
        try:
            policies=ACSPolicyList.model_validate_json(response_dict["response_object"].text)
        except ValidationError as e:
            logger.error(f"Error: {e}")
            logger.info("Content from file is not valid json for ACSPolicyList")
            return

    return policies

async def program_completed_check():
    """
    Checks if the program should end.    
    """
    
    while not ParsedMemory._shutdown:
        if len(ParsedMemory.endpoint_list) == 0:
            logger.info("No ACS Available to Poll")
            if ParsedMemory._initialized:
                ParsedMemory._shutdown = True
            else:
                await asyncio.sleep(10)
            
        else:      
            for ACSEndpoint in ParsedMemory.endpoint_list:
                if ACSEndpoint.parsed == False:
                    logger.info(f"Endpoint {ACSEndpoint.name} not parsed yet")
                    await asyncio.sleep(30)

async def continously_process_healthy_endpoints():
    """
    Method is a continually running policy meant to process healthy endpoints
    """
    endpoint_list = await ParsedMemory.get_healthy_endpoints()
    while True:
        #If we recieved shutdown signal
        if ParsedMemory._shutdown:
            logger.info("Shutting Down")
            break
        
        #Check if there are any healthy endpoints
        if len(endpoint_list.endpoints) == 0:
            #No Healthy Endpoints
            logger.error("No Healthy Endpoints to Poll")
            logger.info(f"Will wait and retry in {settings.health_check_retry_delay} seconds")
            await asyncio.sleep(settings.health_check_retry_delay)
            endpoint_list = await ParsedMemory.get_healthy_endpoints()
            #Restart while loop
            continue
        
        #No need to process any more, we have processed all healthy endpoints we are aware of
        if await ParsedMemory.check_all_healthy_endpoints_processed():
            #All Healthy Endpoints have been processed
            logger.info("All Healthy Endpoints have been processed")
            break

        
        #Must have healthy endpoints to proceed
        for polled_endpoint in endpoint_list.endpoints:
            if polled_endpoint.policies is None:
                endpoint_policies = await get_endpoint_policies(polled_endpoint)
                if endpoint_policies is not None:
                    await ParsedMemory.append_endpoint_policies(polled_endpoint.internal_id,endpoint_policies)      
            #polled_endpoint.processed = True

        
async def main():
    '''App Startup Function'''    
    logger.info("Starting up ACS API Correlation Service")
    global instance_hostname  # pylint: disable=global-statement
  
    # Set Instance Hostname
    logger.info("Instance Hostname: {}".format(settings.instance_hostname))
   
    # Load the ACS Endpoints
    result_endpoint_list = await read_parse_acs_endpoints(settings.endpoint_list_json_path)
    for endpoint in result_endpoint_list.endpoints:
        await ParsedMemory.check_endpoint_valid_healthy(endpoint)                 

    logger.debug("Starting up continously_process_healthy_endpoints")
    asyncio.create_task(continously_process_healthy_endpoints())
    logger.debug("Ending continously_process_healthy_endpoints")
            
        
        

    logger.debug("Starting up Completion Function Check")
    #asyncio.create_task(program_completed_check())
    logger.info("Started up Completion Function Check")

if __name__ == '__main__':
    """
    Entry point for Application
    Application runs  in Asyncio Loop
    If there are no issues the main() function should return and end application after processing
    """
    asyncio.run(main())
 
    