from httpx import AsyncClient,HTTPError,RequestError,TimeoutException,ConnectTimeout
import os
from httpx._config import SSLConfig
from logging import getLogger, config
import typing as t


import logging
try:
    logger = getLogger("logger_root")
except:
    logger = logging.getLogger(__name__)


async def make_request(full_url_path,insecure:bool=False,headers:dict=None,params:dict=None) -> dict:
    """Make a request to the API"""
    error=None
    
    try:
        async with AsyncClient(verify=insecure) as client:        
            response = await client.get(
                f"{full_url_path}",headers=headers,params=params           
            )
            logger.debug(f"request_processing - attempted request")
            response.raise_for_status()       
    except ConnectTimeout as timeout_err:
        logger.error(f" Connect Timeout error occurred: {timeout_err}")
        error=f"Connect Timeout error occurred: {timeout_err}"
    except TimeoutException as timeout_err:
        logger.error(f"Timeout error occurred: {timeout_err}")
        error=f"Timeout error occurred: {timeout_err}"
    except RequestError as req_err:
        logger.error(f"Error occurred while processing request: {req_err}")
        error=f"Error occurred while processing request: {req_err}"
    except HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
        error=f"HTTP error occurred: {http_err}"
    except Exception as e:
        logger.error(f"Other error occurred: {e}")
        error=f"Other error occurred: {e}"
                
    return {"response_object":response,"error_object":error} 

async def request_processing_pagination(full_url_path,insecure:bool=False,headers:dict=None,params:dict=None) -> t.AsyncGenerator[t.Any, None]:
    """
    Args:
        full_url_path (_type_): ACS URL with path for the request
        insecure (bool, optional): Make an insecure Request, Should be set from verify_endpoint_ssl on endpoint object
        headers (dict, optional): Headers for Request to ACS. Defaults to None.
        params (dict, optional): Parameters for Request to ACS. Defaults to None.

    Returns:
        t.AsyncGenerator[t.Any, None]: _description_

    Yields:
        Iterator[t.AsyncGenerator[t.Any, None]]: _description_
    """
    
    #Initalize as any non-zero number
    total_expected_count = 1
    
    if "pagination.limit" not in params:
        logger.error(f"pagination.limit not found in params,Method is only for paginated requests")
        return
        
    if "pagination.offset" not in params:
        params["pagination.offset"] = 0
        
    while True:
        response = await make_request(full_url_path,insecure,headers,params)
        params["pagination.offset"] = params["pagination.offset"] + int(params["pagination.limit"])
        yield response

        if params["pagination.offset"] < total_expected_count:
            break
        page += 1

async def request_processing(full_url_path,insecure:bool=False,headers:dict=None,params:dict=None) -> dict:
    """Send the Request and process the response"""
    logger.debug(f"request_processing -start: url:{full_url_path} verify_ssl:{insecure}")
    error=None
    
    if params is None:
        response_dict = await make_request(full_url_path,insecure,headers,params)
    else:
        if "pagination.limit" in params:
            response_dict= [response async for response in request_processing_pagination(full_url_path,insecure,headers,params)]
        else:
            response_dict = await make_request(full_url_path,insecure,headers,params)
            
    return response_dict

async def get_acs_alert(url,alert_id: str,insecure:bool=False,headers:dict=None,params:dict=None) -> dict:
    """Get ACS alert from the API"""
    logger.debug(f"get_acs_alert -start: url:{url} id:{alert_id} verify_ssl:{insecure}")
    rhacs_alert_url_path=f"{url}/v1/alerts/{alert_id}"
    response_dict = await request_processing(rhacs_alert_url_path,insecure,headers,params)
    logger.debug(f"get_acs_alert - complete")
    return response_dict

async def get_policy(url,insecure:bool=False,headers:dict=None,params:dict=None) -> dict:
    """Get Policy from the API"""
    logger.debug(f"get_policy -start: url:{url} verify_ssl:{insecure}")
    rhacs_policy_url_path=f"{url}/v1/policies"
    response_dict = await request_processing(rhacs_policy_url_path,insecure,headers,params)
    logger.debug(f"get_policy - complete")
    return response_dict

async def get_alert_count(url,insecure:bool=False,headers:dict=None,params:dict=None) -> dict:
    """Get Alert Count"""
    logger.debug(f"get_policy -start: url:{url} verify_ssl:{insecure}")
    rhacs_policy_url_path=f"{url}/v1/policies"
    response_dict = await request_processing(rhacs_policy_url_path,insecure,headers,params)
    logger.debug(f"get_policy - complete")
    return response_dict    
    
async def get_rhacs_health(url,insecure:bool=False,headers:dict=None,params:dict=None) -> dict:
    """Get health from the API"""
    logger.debug(f"get_rhacs_health -start: url:{url}")
    rhacs_health_url_path=f"{url}/v1/ping"
    response_dict = await request_processing(rhacs_health_url_path,insecure,headers,params)
    logger.debug(f"get_rhacs_health - complete")
    return response_dict