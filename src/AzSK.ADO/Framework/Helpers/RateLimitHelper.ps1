Set-StrictMode -Version Latest 
class RateLimitHelper {

    static $RateLimitEntity = [PSCustomObject]@{
        RetryDate = $null
        RateLimitRetryAfter = $null
        RateLimitDelay = $null
        RateLimitReset = $null
    }
    static $APIThrottleCounter = 0
    static $MaxAllowedDelay = $null
    static $MaxAPIThrottledBeforeSleep = $null
    
    <#
        Method to retrieve headers related to rate limiter, store them in rate limit entity variable and send this to telemetry
        Will work only if either UseRateLimit is set to true (in which case it will store appropriate headers in rate limit entity to be used for rate limiting subsequent API calls and also send this data to telemetry) or
        RecordRateLimitDelay is set to true (in which case headers are stored only for telemetry purposes)    
    #>
    static UpdateRateLimitEntity($requestResult,$url){
        try{
            if($env:UseRateLimit -eq $true -or $env:RecordRateLimitDelay -eq $true){
                $responseHeaders = $requestResult.Headers
                $retryAfter = [RateLimitHelper]::GetHeaderValue($responseHeaders, "Retry-After");        
                $rateLimitReset = [RateLimitHelper]::GetHeaderValue($responseHeaders, "X-RateLimit-Reset");
                $rateLimitRemaining = [RateLimitHelper]::GetHeaderValue($responseHeaders, "X-RateLimit-Remaining");
                $rateLimitDelay = [RateLimitHelper]::GetHeaderValue($responseHeaders, "X-RateLimit-Delay");
                <#
                    In case retry after is not null, API has been throttled, get all other headers for rate limiting
                    In case retry after is null, there can be two conditions:
                    1. API has not been throttled (i.e. rate limit remaining is null or greater than 0)
                    2. API has been throttled (i.e. rate limit remaining is 0 and rate limit reset is the time when usage will be reset)
                #> 
                if([string]::IsNullOrEmpty($retryAfter)){
                    if([string]::IsNullOrEmpty($rateLimitRemaining) -or ($rateLimitRemaining -ne 0 -or [string]::IsNullOrEmpty($rateLimitReset))){
                        [RateLimitHelper]::APIThrottleCounter = 0;
                        return;
                    }            
                } 
                #Default behaviour is to ignore all delays less than 1 sec to improve scan time, can be overrrided by OverrideRateLimitThreshold
                if($env:OverrideRateLimitThreshold -ne $true){
                    if(-not [string]::IsNullOrEmpty($rateLimitDelay) -and $rateLimitDelay -lt 1){
                        [RateLimitHelper]::APIThrottleCounter = 0;
                        return;
                    }
                }                  
                $rateLimitResetDate = (Get-Date 01.01.1970) + ([System.TimeSpan]::FromSeconds($rateLimitReset));
                #in case retry after is null retry should be done on the basis of rate limit reset date
                if(-not [string]::IsNullOrEmpty($retryAfter)){
                    $retryAfterDate = ([DateTime]::UtcNow).AddSeconds($retryAfter);
                }
                else{
                    $retryAfterDate = $rateLimitResetDate
                }
                [RateLimitHelper]::RateLimitEntity.RetryDate = $retryAfterDate;
                [RateLimitHelper]::RateLimitEntity.RateLimitRetryAfter = $retryAfter;
                [RateLimitHelper]::RateLimitEntity.RateLimitDelay = $rateLimitDelay;
                [RateLimitHelper]::RateLimitEntity.RateLimitReset = $rateLimitResetDate;
                $eventName = "Delay from API: $($url)";
                $eventProps = [RateLimitHelper]::RateLimitEntity;
                [RateLimitHelper]::SendDelayEventToTelemetry($eventName,$eventProps);
                [RateLimitHelper]::APIThrottleCounter+=1
            }
            
        }
        catch{
            $eventName = "Error in updating: "+$_;
            [RateLimitHelper]::SendDelayEventToTelemetry($_,$null);
        }
        
        
    }

    <#
        Method to get value from a response header
    #>
    static [string] GetHeaderValue($responseHeaders, $header){
        $result = $null;
        try{
            if($responseHeaders.ContainsKey($header)){
                $result = $responseHeaders[$header]
            }
        }
        catch{
            $eventName = "Could not retrieve value for $($responseHeaders[$header]) ";
            [RateLimitHelper]::SendDelayEventToTelemetry($eventName,$null);
        }
        
        return $result;
    }

    <#
        Method to retrieve rate limiting constants from config, will be called only once
        Has been put in try catch block as the scan will error out completely in case the org policy is outdated/ hasn't been set properly
    #>
    static [void] SetRateLimitConstants(){
        try{
            $ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
            [RateLimitHelper]::MaxAllowedDelay = $ControlSettings.RateLimiter.MaxAllowedDelay;
            [RateLimitHelper]::MaxAPIThrottledBeforeSleep = $ControlSettings.RateLimiter.MaxAPIThrottledBeforeSleep;
        }
        catch{
            [RateLimitHelper]::MaxAllowedDelay = 300
            [RateLimitHelper]::MaxAPIThrottledBeforeSleep = 10
        }          
        
    }

    <#
        Method to rate limit APIs in case throttling is detected, will work only if UseRateLimit is set to true
    #>
    static WaitIfNeeded($url){
        try{
            if($env:UseRateLimit -eq $true){
                #Get necessary constants from config, will be called only once
                if($null -eq [RateLimitHelper]::MaxAllowedDelay){
                    [RateLimitHelper]::SetRateLimitConstants();
                }
                #in case more than 10 APIs have been throttled back to back, shut down the scan for 10 mins
                if([RateLimitHelper]::APIThrottleCounter -gt [RateLimitHelper]::MaxAPIThrottledBeforeSleep){
                    $eventName = "10 consecutive APIs have been delayed. Stopping scan for 10 minutes";
                    [RateLimitHelper]::SendDelayEventToTelemetry($eventName,$null);
                    Start-Sleep -Seconds 600;
                    [RateLimitHelper]::APIThrottleCounter = 0;
                }
                $retryAfterDate = [RateLimitHelper]::RateLimitEntity.RetryDate;        
                if($null -eq $retryAfterDate -or [DateTime]::UtcNow -gt $retryAfterDate){
                    return;
                }
                $delayAmount = ($retryAfterDate - [DateTime]::UtcNow).TotalSeconds
                $delayEvent = [PSCustomObject]@{
                    URL = $url
                    Delay = $delayAmount
                }
                #in case delay from API is greater than 5 mins, do not stop the scan, send this data to telemetry
                if($delayAmount -gt [RateLimitHelper]::MaxAllowedDelay){
                    $eventName = "Terminating API call instead of waiting for $($delayAmount) for API: $($url)"
                    [RateLimitHelper]::SendDelayEventToTelemetry($eventName,$delayEvent);
                    return;
                }
                if($delayAmount -eq 0){
                    return;
                }
                
                $eventName = "RateLimiter: Wait initiated for $($delayAmount) seconds for API: $($url)";
                [RateLimitHelper]::SendDelayEventToTelemetry($eventName,$delayEvent);
                Start-Sleep -Seconds $delayAmount;
            }
            
        }
        catch{
            $eventName = "Error in waiting: "+$_;
            [RateLimitHelper]::SendDelayEventToTelemetry($_,$null);
        }
        
    }

    <#
        Method to send data to telemetry.
        The universal telemetry helper class has not been used here due to circular dependencies in framework
        Data will be sent to the app insights of the function app
    #>
    static SendDelayEventToTelemetry($eventName, $eventProps){
        $telemetryClient = [Microsoft.ApplicationInsights.TelemetryClient]::new();
        $telemetryClient.InstrumentationKey = $env:APPINSIGHTS_INSTRUMENTATIONKEY;       
        $event = [Microsoft.ApplicationInsights.DataContracts.EventTelemetry]::new()
        $event.Name = $eventName
        if($null -ne $eventProps){
            
            $eventProps.PSObject.Properties | ForEach-Object {
                try {
                    $event.Properties[$_.Name] = $_.Value.ToString();
                }
                catch
				{
                    $_
					# Eat the current exception which typically happens when the property already exist in the object and try to add the same property again
					# No need to break execution
				}
            }
        }
        $telemetryClient.TrackEvent($event);

    }

}