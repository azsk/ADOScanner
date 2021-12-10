using namespace Newtonsoft.Json
using namespace Microsoft.Azure.Commands.Common.Authentication.Abstractions
using namespace Microsoft.Azure.Commands.Common.Authentication
using namespace Microsoft.Azure.Management.Storage.Models
Set-StrictMode -Version Latest
class InventoryHelper {
    # getting resources count and sending them to telemetry as well
    static GetResourceCount($organizationName, $projectName, $projectId, $projectData) {
        try {
            # fetching the repository count of a project
            try {
                $resourceURL = "https://dev.azure.com/$($organizationName)/$($projectName)/_apis/git/repositories?api-version=6.1-preview.1"
                $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
                if (([Helpers]::CheckMember($responseList, "count") -and $responseList[0].count -gt 0) -or (($responseList | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($responseList[0], "name"))) {
                    $projectData['Repositories'] = ($responseList | Measure-Object).Count
                }
            }
            catch {}
            # fetching the testPlan count of a project
            try {
                $resourceURL = "https://dev.azure.com/$($organizationName)/$($projectName)/_apis/testplan/plans?api-version=6.0-preview.1"
                $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
                if (([Helpers]::CheckMember($responseList, "count") -and $responseList[0].count -gt 0) -or (($responseList | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($responseList[0], "name"))) {
                    $projectData['TestPlans'] = ($responseList | Measure-Object).Count
                }
            }
            catch {}

            try {
                # fetching the taskGroups count of a project
                $resourceURL = "https://dev.azure.com/$($organizationName)/$($projectName)/_apis/distributedtask/taskgroups?api-version=6.0-preview.1"
                $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
                if (([Helpers]::CheckMember($responseList, "count") -and $responseList[0].count -gt 0) -or (($responseList | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($responseList[0], "name"))) {
                    $projectData['TaskGroups'] = ($responseList | Measure-Object).Count
                }
            }
            catch {}

            # fetch the builds count
            try {
                $resourceURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?api-version=6.0&queryOrder=lastModifiedDescending&`$top=10000") -f $($organizationName), $projectName;
                $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL);
                if (([Helpers]::CheckMember($responseList, "count") -and $responseList[0].count -gt 0) -or (($responseList | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($responseList[0], "name"))) {
                    $projectData['Build'] = ($responseList | Measure-Object).Count
                }
            }
            catch {}

            # fetch the release count
            try {
                $resourceURL = ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=6.0") -f $($organizationName), $projectName;
                $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL);
                if (([Helpers]::CheckMember($responseList, "count") -and $responseList[0].count -gt 0) -or (($responseList | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($responseList[0], "name"))) {
                    $projectData['Release'] = ($responseList | Measure-Object).Count
                }
            }
            catch {}

            # fetch the service connections count
            try {
                $resourceURL = ("https://dev.azure.com/{0}/{1}/_apis/serviceendpoint/endpoints?includeDetails=True&api-version=6.0-preview.4") -f $($organizationName), $($projectName);
                $serviceEndpointObj = [WebRequestHelper]::InvokeGetWebRequest($resourceURL)
                if (([Helpers]::CheckMember($serviceEndpointObj, "count") -and $serviceEndpointObj[0].count -gt 0) -or (($serviceEndpointObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($serviceEndpointObj[0], "name"))) {
                    $projectData['ServiceConnections'] = ($serviceEndpointObj | Measure-Object).Count
                }
            }
            catch {}

            # fetch the agent pools count
            try {
                if ($projectData["AgentPools"] -eq -1 -or  $projectData["AgentPools"] -eq 0) {
                    $agentPoolsDefnURL = ("https://dev.azure.com/{0}/{1}/_settings/agentqueues?__rt=fps&__ver=2") -f $($organizationName), $projectName;
                    $agentPoolsDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsDefnURL);
                    if (([Helpers]::CheckMember($agentPoolsDefnsObj, "fps.dataProviders.data") ) -and (($agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider") -and $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues)) {
                        $taskAgentQueues = $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues;
                        
                        # We need to filter out legacy agent pools (Hosted, Hosted VS 2017 etc.) as they are not visible to user on the portal. As a result, they won't be able to remediate their respective controls
                        $taskAgentQueues = $taskAgentQueues | where-object{$_.pool.isLegacy -eq $false};
                        
                        #Filtering out "Azure Pipelines" agent pool from scan as it is created by ADO by default and some of its settings are not editable (grant access to all pipelines, auto-provisioning etc.)
                        $taskAgentQueues = $taskAgentQueues | where-object{$_.name -ne "Azure Pipelines"};
                        $projectData["AgentPools"] = ($taskAgentQueues | Measure-Object).Count
                    }
                }
            }
            catch {}

            # fetch the variable groups count
            try {
                if ($projectData["VariableGroups"] -eq -1 -or $projectData["VariableGroups"] -eq 0) {
                    $variableGroupURL = ("https://dev.azure.com/{0}/{1}/_apis/distributedtask/variablegroups?api-version=6.1-preview.2") -f $($organizationName), $projectId;
                    $variableGroupObj = [WebRequestHelper]::InvokeGetWebRequest($variableGroupURL)
                    if (([Helpers]::CheckMember($variableGroupObj, "count") -and $variableGroupObj[0].count -gt 0) -or (($variableGroupObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($variableGroupObj[0], "name"))) {
                        $varGroups = $variableGroupObj
                        $projectData["VariableGroups"] = ($varGroups | Measure-Object).Count
                    }
                }
            }
            catch {}

            # fetch the secure files count
            try {
                if ($projectData["SecureFiles"] -eq 0) {
                    $secureFileDefnURL = ("https://dev.azure.com/{0}/{1}/_apis/distributedtask/securefiles?api-version=6.1-preview.1") -f $($organizationName), $projectName;
                    $secureFileObj = [WebRequestHelper]::InvokeGetWebRequest($secureFileDefnURL)
                    if (([Helpers]::CheckMember($secureFileObj, "count") -and $secureFileObj[0].count -gt 0) -or (($secureFileObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($secureFileObj[0], "name"))) {
                        $projectData["SecureFiles"] = ($secureFileObj | Measure-Object).Count
                    }
                }
            }
            catch {}

            # fetch the feeds count
            try {
                if ($projectData["Feeds"] -eq 0) {
                    $feedDefnURL = ("https://feeds.dev.azure.com/{0}/{1}/_apis/packaging/feeds?api-version=6.0-preview.1") -f $organizationName, $projectName
                    $feedDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($feedDefnURL);
                    if (([Helpers]::CheckMember($feedDefnsObj, "count") -and $feedDefnsObj[0].count -gt 0) -or (($feedDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($feedDefnsObj[0], "name"))) {
                        $projectData["Feeds"] = ($feedDefnsObj | Measure-Object).Count
                    }
                }
            }
            catch {}

            # fetch the environments count
            try {
                if ($projectData["Environments"] -eq 0) {
                    #$topNQueryString = '&$top=10000'
                    $environmentDefnURL = ("https://dev.azure.com/{0}/{1}/_apis/distributedtask/environments?api-version=6.0-preview.1") -f $organizationName, $projectName;
                    $environmentDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($environmentDefnURL);
                    if (([Helpers]::CheckMember($environmentDefnsObj, "count") -and $environmentDefnsObj[0].count -gt 0) -or (($environmentDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($environmentDefnsObj[0], "name"))) {
                        $projectData["Environments"] = ($environmentDefnsObj | Measure-Object).Count
                    }
                }
            }
            catch {}
        }
        catch {
        }
        [AIOrgTelemetryHelper]::PublishEvent("Projects resources count", $projectData, @{})
    }

}

