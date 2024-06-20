import asyncio
from os import path, getenv
from signal import SIGTERM
from logging import getLogger, config
from acs_request import get_acs_alert, get_rhacs_health,get_policy,get_alert_count,get_acs_deployment
from pydantic import BaseModel, SecretStr, ValidationError, Field
from pydantic_core import from_json
from aiofiles import open as async_open, os as aiofiles_os
from typing import Any, Optional, AsyncGenerator, Any
from config import settings
from typing_extensions import Annotated
from uuid import uuid4, UUID


class ACSAlertCount(BaseModel):
    count: int
    
class ACSViolations(BaseModel):
    message: str

class ACSImageDetails(BaseModel):
    registry: Optional[str] = None
    remote: Optional[str] = None
    fullName: Optional[str] = None
    tag: Optional[str] = None

class ACSImage(BaseModel):
    id: Optional[str] = None
    name: Optional[ACSImageDetails] = None
    notPullable: Optional[bool] = None
    isClusterLocal: Optional[bool] = None

class ACSContainer(BaseModel):
    name: Optional[str] = None
    image: Optional[ACSImage] = None
    securityContext: Optional[dict] = None
    volumes: Optional[list] = None
    ports: Optional[list] = None
    secrets: Optional[list] = None
    resources: Optional[dict] = None
    livenessProbe: Optional[dict] = None
    readinessProbe: Optional[dict] = None

class ACSContainerlist(BaseModel):
    containers: list[ACSContainer]
    
class ACSDeployment(BaseModel):
    '''Affected RHACS Deployment as received from Vulnerability Data'''
    id: str
    name: Optional[str]
    type: Optional[str] = None
    namespace: Optional[str] = None
    namespaceId: Optional[str] = None
    orchestratorComponent: Optional[bool] = None
    replicas: Optional[int] = None
    created: Optional[str] = None
    labels: Optional[dict] = None
    clusterId: Optional[str] = None
    clusterName: Optional[str] = None
    containers: Optional [list] = None
    annotations: Optional[dict] = None
    inactive: Optional[bool] = None
    priority: Optional[str] = None
    imagePullSecrets: Optional[list] = None
    serviceAccount:Optional[str] = None
    tolerations: Optional[list] = None
    nodeSelector: Optional[dict] = None
    riskScore: Optional[float] = None
    stateTimestamp: Optional[str] = None
    ports:  Optional[list] = None
    #Fields below were added to help correlation
    metadata_processed: Optional[bool] = False
    alerts: Optional[list] = []

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
    disabled: Optional[bool] = None
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
    #Fields below were added to help correlation
    #Violation Count keeps track of number of alerts for this policy
    violation_count: Optional[int] = None
    metadata_processed: Optional[bool] = False
        
class ACSPolicyList(BaseModel):
    '''App Object - List of Policies obtained from ACS'''
    policies: list[ACSPolicy]
    endpoint_uuid: UUID = None
      
    async def get_policy_count(self):
        return len(self.policies)       
        
class ACSAlert(BaseModel):  
    '''Class For Alert Information from RHACS'''
    id: str
    policy: Optional[ACSPolicy] = None
    clusterId: Optional[str] = None
    clusterName: Optional[str] = None
    namespace: Optional[str] = None
    namespaceId:Optional[str] = None
    deployment: Optional[ACSDeployment] = None
    resource: Optional[dict] = None
    violations: Optional[ACSViolations] = None
    time: str
    firstOccurred: Optional[str] = None
    lifecycleStage: Optional[str] = None
    resolvedAt: Optional[str] = None
    state: Optional[str] = None
    snoozeTill: Optional[str] = None
    enforcement: Optional[str] = None
    #Added below to help with correlation
    metadata_processed: Optional[bool] = False

class ACSAlertList(BaseModel):
    '''App Object - List of Alerts obtained from RHACS'''
    alerts: list[ACSAlert]
    
    async def get_alert_count(self):
        return len(self.alerts)

class OCPCluster(BaseModel):
    '''Class For OCP Cluster Information'''
    cluster_id: str
    cluster_name: str
    deployments: list[ACSDeployment]

class OCPClusterlist(BaseModel):
    '''App Object - List of OCP Clusters'''
    clusters: list[OCPCluster]
    
class ACSEndpoint(BaseModel):
    '''App Object - ACS Endpoint Information'''
    internal_id: UUID = Field(default_factory=uuid4)
    endpoint_name: str
    endpoint_url: str
    endpoint_token_env_variable_name: str
    endpoint_token: SecretStr = "Empty"
    verify_endpoint_ssl: bool = False
    healthy: bool = False
    metadata_processed: Optional[bool] = False
    initialized:bool = False
    endpoint_url_description: str = "ACS API endpoint for the application to make request to"
    endpoint_token_env_variable_name_description:str = "Environment Variable to retrieve the Token for this cluster"
    policies: ACSPolicyList = ACSPolicyList(policies=[])
    
    def get_health(self) -> bool:
        if not self.initialized:
            return False      
        return self.healthy
    
    def set_health(self,health:bool) -> None:
        self.healthy = health
    
class ACSEndpointList(BaseModel):
    '''App Object - ACS Endpoint List'''
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
    _all_healthy_endpoints_processed = False
    _all_policies_processed =  False
    _all_alerts_processed = False
    _all_deployments_processed = False
    all_metadata_processed = False
    endpoint_list: ACSEndpointList = ACSEndpointList(endpoints=[])
    alert_list: ACSAlertList = ACSAlertList(alerts=[])
    policy_list: ACSPolicyList = ACSPolicyList(policies=[])
    ocp_clusters: OCPClusterlist = OCPClusterlist(clusters=[])
    deployment_list = []
    map_cluster_id_cluster_object = {}
    map_endpoint_uuid_endpoint_object = {}
    map_endpoint_uuid_policy_object = {}
    map_policy_id_alert_list = {}
    map_alert_id_endpoint_object = {}

    @classmethod
    async def get_endpoint_count(cls) -> int:
        """
        Get the count of Endpoints
        """
        async with cls._lock:
            return len(cls.endpoint_list.endpoints)
        
    @classmethod
    async def get_endpoint_by_uuid(cls,endpoint_uuid) -> ACSEndpoint:
        """
        Get the Endpoint by UUID
        """
        async with cls._lock:
            try:
                return [ endpoint for endpoint in cls.endpoint_list.endpoints if endpoint.internal_id == endpoint_uuid ][0]
            except Exception as e:
                logger.error(f"Endpoint {endpoint_uuid} not found in the list of ACS endpoints")
                logger.error(f"Error: {e}")
                return None

    @classmethod
    async def get_endpoint_names(cls) -> list[str]:
        """
        Get the list of Endpoint Names
        """
        async with cls._lock:
            return [endpoint.endpoint_name for endpoint in cls.endpoint_list.endpoints]
    
    @classmethod
    async def get_healthy_endpoints(cls) -> ACSEndpointList:
        """
        Get the list of Healthy Endpoints
        """
        async with cls._lock:
            return cls.endpoint_list           

    @classmethod
    async def check_all_policies_processed(cls) -> bool:
        """
        Check if all Policies have been processed
        """
            
        if cls._all_policies_processed:
            return cls._all_policies_processed
        
        async with cls._lock:
            if not len(cls.policy_list.policies) > 0:
                return False
            
            for policy in cls.policy_list.policies:
                if not policy.metadata_processed:
                    return False
            cls._all_policies_processed = True
            return True

    @classmethod
    async def check_all_alerts_processed(cls) -> bool:
        """
        Check if all Alerts have been processed
        """
        if cls._all_alerts_processed:
            return cls._all_alerts_processed
        
        async with cls._lock:
            if not len(cls.alert_list.alerts) > 0:
                return False
            
            for alert in cls.alert_list.alerts:
                if not alert.metadata_processed:
                    return False
            cls._all_alerts_processed = True
            return True
        
    @classmethod
    async def check_all_healthy_endpoints_processed(cls) -> bool:
        """
        Check if all Healthy Endpoints have been processed
        """
        
        if cls._all_healthy_endpoints_processed:
            return cls._all_healthy_endpoints_processed
            
        async with cls._lock:
            if not len(cls.endpoint_list.endpoints) > 0:
                return False
            
            for endpoint in cls.endpoint_list.endpoints:
                if endpoint.get_health() and not endpoint.metadata_processed:
                    return False
            cls._all_healthy_endpoints_processed = True #Once set to True, we will not check again to save time
            return True

    @classmethod
    async def check_all_deployments_processed(cls) -> bool:
        """
        Check if all Deployments have been processed
        """
        
        if cls._all_deployments_processed:
            return cls._all_deployments_processed
        
        async with cls._lock:
            if not len(cls.deployment_list) > 0:
                return False
            
            for deployment in cls.deployment_list:
                if not deployment.metadata_processed:
                    return False
            cls._all_deployments_processed = True
            return True
        
    @classmethod
    async def check_are_all_endpoints_unhealthy(cls) -> bool:
        """
        Check if there are no healthy endpoints
        """
        async with cls._lock:
            for endpoint in cls.endpoint_list.endpoints:
                if endpoint.get_health():
                    return False
            return True
                             
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
                if "error_object" in response_dict and response_dict["error_object"] is not None:
                    logger.error(f"Policy Data Not Retrieved for Endpoint {ACSEndpoint.endpoint_name}")
                    logger.error(f"Error: {response_dict['error_object']}")
                    continue
                
                if response_dict["response_object"].status_code == 200:
                    logger.info(f"ACS API Connection Successful for Endpoint {ACS_Endpoint.endpoint_name} ")
                    ACS_Endpoint.set_health(True)
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
    
    @classmethod
    async def append_policy_alertcount(cls,count,ACSPolicy:ACSPolicy) -> bool:
        """
        Append the Alert Count to the Policy
        """
        async with cls._lock:
            try:
                ACSPolicy.violation_count = count
                logger.debug(f"Alert Count for Policy {ACSPolicy.name} updated")
            except:
                logger.error(f"Error appending Alert Count for Policy {ACSPolicy.name} to the list")
                return False
        return True
            
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
                    ACSPolicyList.endpoint_uuid = endpoint_uuid
                    for policy in ACSPolicyList.policies:
                        cls.map_endpoint_uuid_policy_object[endpoint_uuid] = policy
                        policy.metadata_processed = True
                    cls.policy_list.policies = cls.policy_list.policies + ACSPolicyList.policies
                    logger.info(f"Policy Data for Endpoint {endpoint.endpoint_name} appended to the list of ACS endpoints")
                else:
                    logger.error(f"Endpoint {endpoint_uuid} not found in the list of ACS endpoints")
                    return False
            except Exception as e:
                logger.error(f"Endpoint {endpoint_uuid} not found in the list of ACS endpoints")
                logger.error(f"Error: {e}")
                return False

    @classmethod
    async def append_endpoint(cls,ACS_Endpoint:ACSEndpoint) -> bool:
        """
        Append Endpoint to the List
        """
        async with cls._lock:
            try:
                if ACS_Endpoint.get_health():
                    cls.endpoint_list.endpoints.append(ACS_Endpoint)
                    ACS_Endpoint.initialized = True
                    cls.map_endpoint_uuid_endpoint_object[ACS_Endpoint.internal_id] = ACS_Endpoint
                    ACS_Endpoint.metadata_processed = True
                    logger.info(f"Endpoint {ACS_Endpoint.endpoint_name} healthy and appended to the list of ACS endpoints to be polled")
            except Exception as e:
                logger.error(f"Error appending Endpoint {ACS_Endpoint.endpoint_name} to the list")
                logger.error(f"Error: {e}")
                return False
        return True

    @classmethod
    async def append_alert(cls,ACSAlertList:ACSAlertList,ACSEndpoint:ACSEndpoint,ACSPolicy) -> bool:
        """
        Append Alert to the List
        """
        async with cls._lock:
            try:                            
                cls.alert_list.alerts= cls.alert_list.alerts + ACSAlertList.alerts
                cls.map_alert_id_endpoint_object.update({alert.id:ACSEndpoint for alert in ACSAlertList.alerts})  
                if ACSPolicy.id in cls.map_policy_id_alert_list.keys():
                    cls.map_policy_id_alert_list[ACSPolicy.id].alerts = cls.map_policy_id_alert_list[ACSPolicy.id].alerts + ACSAlertList.alerts
                else:
                    cls.map_policy_id_alert_list[ACSPolicy.id] = ACSAlertList 
                
                for alert in ACSAlertList.alerts:
                    alert.metadata_processed = True                    
                    if alert.policy is not None:
                        if alert.policy.id == ACSPolicy.id:
                            #No need to maintain 2 policy objects with the same information
                            alert.policy=ACSPolicy     
                logger.debug(f"Alert appended to the list of Alerts")
            except Exception as e:
                logger.error(f"Error: {e}")
                return False
        return True

    @classmethod
    async def append_deployment(cls,ACSDeployment:ACSDeployment,ACSAlert:ACSAlert) -> bool:
        """
        Append Deployment to the List
        """
        async with cls._lock:
            try:
                ACSDeployment.alerts.append(ACSAlert)
                cls.deployment_list.append(ACSDeployment)
                if ACSDeployment.clusterId in cls.map_cluster_id_cluster_object.keys():
                    cls.map_cluster_id_cluster_object[ACSDeployment.clusterId].deployments.append(ACSDeployment)
                else:
                    temp_cluster = OCPCluster(cluster_id=ACSDeployment.clusterId,cluster_name=ACSDeployment.clusterName,deployments=[ACSDeployment])
                    cls.ocp_clusters.clusters.append(temp_cluster)
                    cls.map_cluster_id_cluster_object[ACSDeployment.clusterId] = temp_cluster
                ACSDeployment.metadata_processed = True
                logger.debug(f"Deployment appended to the list of Deployments")
            except Exception as e:
                logger.error(f"Error: {e}")
                return False
        return True
        
        
        
# ------------------------------------------------------------------------------------------------
# App Init and Global Variables
# ------------------------------------------------------------------------------------------------
# Logging
log_file_path = path.join(path.dirname(path.abspath(__file__)), 'logging.conf')
config.fileConfig(log_file_path, disable_existing_loggers=False)
logger = getLogger("logger_root")


async def write_output_file(file_path: str, content: str) -> None:
    """
    Write the content to a file
    """
    logger.info(f"Writing content to file - ({file_path})")
    try:
        async with async_open(file_path, mode='w+') as filehandle:
            await filehandle.write(content)
    except OSError as e:
        logger.error(f"Error writing content to file - ({file_path})")
        logger.error(f"Error: {e}")
        return
    except ValueError as e:
        # Non-encodable path
        logger.error(f"Error writing content to file - ({file_path})")
        logger.error(f"Error: {e}")
        return
    
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

async def update_endpoint_policy_alert_count(ACSEndpoint:ACSEndpoint,ACSPolicyList:ACSPolicyList) -> None:
    """
    Update the Policy Alert Count
    """
    
    for policy in ACSPolicyList.policies:
        
        #We dont' want to update policys' that are disabled
        if settings.poll_disabled_policy_info == False and policy.disabled:
            continue
        
        #No need to re-update the policy if we already have the alert count
        if policy.violation_count is not None:
            continue
            
        logger.debug(f"Updating Policy {policy.name} Alert Count")
        headers={"Authorization": f"Bearer {ACSEndpoint.endpoint_token}",
                 "Content-Type": "application/json"}
        params={"query": f"Policy:{policy.name}"}
        
        response_dict = await get_alert_count(ACSEndpoint.endpoint_url,ACSEndpoint.verify_endpoint_ssl,headers,params)
        
        if "error_object" in response_dict and response_dict["error_object"] is not None:
            logger.error(f"Failed getting Alert count for {policy.name}")
            logger.error(f"Error: {response_dict['error_object']}")
            continue
        
        if response_dict["response_object"].status_code == 200:
            logger.debug(f"Retrieved Alert count for {policy.name}")
            try:
                alertcount=ACSAlertCount.model_validate_json(response_dict["response_object"].text)
            except ValidationError as e:
                logger.error(f"Error: {e}")
                logger.info("Content from file is not valid json for ACSPolicyList")
                continue
            
            await ParsedMemory.append_policy_alertcount(alertcount.count,policy)

async def get_alerts_for_policy(ACSEndpoint:ACSEndpoint,ACSPolicy:ACSPolicy) -> ACSAlert:
    """_summary_

    Args:
        ACSEndpoint (ACSEndpoint): _description_
        ACSPolicy (ACSPolicy): _description_

    Returns:
        ACSAlert: _description_
    """
    logger.debug(f"Getting alerts for policy {ACSPolicy.name}")
    params={"query": f"Policy:{ACSPolicy.name}","pagination.limit": 100,"pagination.offset": 0,"pagination.total_expected_count": ACSPolicy.violation_count}

    headers={"Authorization": f"Bearer {ACSEndpoint.endpoint_token}",
                 "Content-Type": "application/json"}
    
    response_dict = await get_acs_alert(ACSEndpoint.endpoint_url,None,ACSEndpoint.verify_endpoint_ssl,headers,params)
    if "error_object" in response_dict and response_dict["error_object"] is not None:
        logger.error(f"Failed getting Alerts for Policy {ACSPolicy.name}")
        logger.error(f"Error: {response_dict['error_object']}")
        return
    try:
        for alert in response_dict["response_object"]:
            parsed_alert=ACSAlertList.model_validate_json(alert.text)
            await ParsedMemory.append_alert(parsed_alert,ACSEndpoint,ACSPolicy)
    except ValidationError as e:
        logger.error(f"Error: {e}")
        logger.info("Content from file is not valid json for ASCSAlert")
        return
    
async def get_deployment_metadata_for_alert(alert:ACSAlert,ACSEndpoint:ACSEndpoint) -> ACSDeployment:
    
    logger.debug(f"Getting Deployment metadata for Alert")
    headers={"Authorization": f"Bearer {ACSEndpoint.endpoint_token}",
                 "Content-Type": "application/json"}
    
    if alert.deployment is None:
        logger.debug(f"Deployment Information not available for Alert {alert.id}")
        return
    deployment_id = alert.deployment.id
    response_dict = await get_acs_deployment(ACSEndpoint.endpoint_url,deployment_id,ACSEndpoint.verify_endpoint_ssl,headers,params=None)
    if "error_object" in response_dict and response_dict["error_object"] is not None:
        logger.error(f"Failed getting Alerts for Alert {alert.id}")
        logger.error(f"Error: {response_dict['error_object']}")
        return
    
    if response_dict["response_object"].status_code == 200:
        try:
            deployment=ACSDeployment.model_validate_json(response_dict["response_object"].text)
            await ParsedMemory.append_deployment(deployment,alert)
        except ValidationError as e:
            logger.error(f"Error: {e}")
            return
                                           
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
 
        #Section checks if we dont need to process any more, as we have processed all data
        if await ParsedMemory.check_all_healthy_endpoints_processed():
            #All Healthy Endpoints have been processed
            logger.debug("All Healthy Endpoints have been processed, checking policies")          
            if await ParsedMemory.check_all_policies_processed():
                #All Policies have been processed
                logger.debug("All Policies have been processed, checking alerts")
                if await ParsedMemory.check_all_alerts_processed():
                    #All Alerts have been processed
                    logger.debug("All Alerts have been processed, checking deployments")
                    if await ParsedMemory.check_all_deployments_processed():
                        #All Deployments have been processed
                        logger.info("All Data has been processed")
                        ParsedMemory.all_metadata_processed = True    
                        break

        #Check if there are any healthy endpoints
        if endpoint_list is not None and len(endpoint_list.endpoints) == 0:
            #No Healthy Endpoints
            logger.error("No Healthy Endpoints to Poll")
            logger.info(f"Will wait and retry in {settings.health_check_retry_delay} seconds")
            await asyncio.sleep(settings.health_check_retry_delay)
            endpoint_list = await ParsedMemory.get_healthy_endpoints()
            #Restart while loop
            continue

        #Must have healthy endpoints to proceed
        for polled_endpoint in endpoint_list.endpoints:
            if await polled_endpoint.policies.get_policy_count() == 0:
                endpoint_policies = await get_endpoint_policies(polled_endpoint)
                if endpoint_policies is not None:
                    await ParsedMemory.append_endpoint_policies(polled_endpoint.internal_id,endpoint_policies)
        
        #Obtain the AlertCount for Policies          
        for polled_endpoint in endpoint_list.endpoints:
            if await polled_endpoint.policies.get_policy_count() != 0:
                await update_endpoint_policy_alert_count(polled_endpoint,polled_endpoint.policies)

        #Obtain Alerts for Policies we are aware
        for polled_endpoint in endpoint_list.endpoints:
            if await polled_endpoint.policies.get_policy_count() != 0: #There is no need to get alerts for endpoints that have no policies
                await asyncio.gather(*[get_alerts_for_policy(polled_endpoint,policy) 
                                       for policy in polled_endpoint.policies.policies 
                                       if policy.violation_count != 0 #There is no need to get alerts for policies we already know have no alerts
                                       and policy.violation_count is not None #There is no need to get alerts for policies we have no alert count for(We are prob still waiting for the alert count to be updated due to async)
                                       and policy.id not in ParsedMemory.map_policy_id_alert_list.keys()]) #There is no need to get alerts for policies we have already gotten alerts for
                    
        #Obtain Deployment Information/Metadata for Alerts
        for alert in ParsedMemory.alert_list.alerts:
            if alert.deployment is not None: #Some alerts are cluster level and not pertaining to a deployment
                await get_deployment_metadata_for_alert(alert,ParsedMemory.map_alert_id_endpoint_object[alert.id])
            else:
                logger.debug(f"Alert {alert.id} does not have deployment information")
                alert.metadata_processed = True             

async def generate_cluster_deployment_output():
    """
    Generate the output for the Cluster and Deployment
    """
    logger.info("Generating Output for Cluster and Deployment")
    output_content = ParsedMemory.ocp_clusters.model_dump_json(indent=4)
    output_file = path.join(settings.output_folder, 'cluster_deployment_output.json')
    await write_output_file(output_file, output_content)
           
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

    logger.debug("Starting up continously_process_healthy_endpoints for metadata")
    asyncio.create_task(continously_process_healthy_endpoints())
    logger.debug("Ending continously_process_healthy_endpoints for metadata")
    
    #Generate output Files
    while True:
        if ParsedMemory.all_metadata_processed:
            await generate_cluster_deployment_output()
            break
        else:
            logger.info("Waiting for all data to be processed before generating output")
            await asyncio.sleep(30)
            
    
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
 
    