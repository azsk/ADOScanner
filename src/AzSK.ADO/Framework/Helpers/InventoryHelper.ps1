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
            $resourceURL = "https://dev.azure.com/$($organizationName)/$($projectName)/_apis/git/repositories?api-version=6.1-preview.1"
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
            if (([Helpers]::CheckMember($responseList, "count") -and $responseList[0].count -gt 0) -or (($responseList | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($responseList[0], "name"))) {
                $projectData['Repositories'] = ($responseList | Measure-Object).Count
            }

            # fetching the testPlan count of a project
            $resourceURL = "https://dev.azure.com/$($organizationName)/$($projectName)/_apis/testplan/plans?api-version=6.0-preview.1"
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
            if (([Helpers]::CheckMember($responseList, "count") -and $responseList[0].count -gt 0) -or (($responseList | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($responseList[0], "name"))) {
                $projectData['TestPlans'] = ($responseList | Measure-Object).Count
            }

            # fetching the taskGroups count of a project
            $resourceURL = "https://dev.azure.com/$($organizationName)/$($projectName)/_apis/distributedtask/taskgroups?api-version=6.0-preview.1"
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
            if (([Helpers]::CheckMember($responseList, "count") -and $responseList[0].count -gt 0) -or (($responseList | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($responseList[0], "name"))) {
                $projectData['TaskGroups'] = ($responseList | Measure-Object).Count
            }

            # fetch the builds count
            $resourceURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?api-version=6.0&queryOrder=lastModifiedDescending&`$top=10000") -f $($organizationName), $projectName;
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL);
            if (([Helpers]::CheckMember($responseList, "count") -and $responseList[0].count -gt 0) -or (($responseList | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($responseList[0], "name"))) {
                $projectData['Build'] = ($responseList | Measure-Object).Count
            }

            # fetch the release count
            $resourceURL = ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=6.0") -f $($organizationName), $projectName;
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL);
            if (([Helpers]::CheckMember($responseList, "count") -and $responseList[0].count -gt 0) -or (($responseList | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($responseList[0], "name"))) {
                $projectData['Release'] = ($responseList | Measure-Object).Count
            }

            # fetch the service connections count
            $resourceURL = ("https://dev.azure.com/{0}/{1}/_apis/serviceendpoint/endpoints?includeDetails=True&api-version=6.0-preview.4") -f $($organizationName), $($projectName);
            $serviceEndpointObj = [WebRequestHelper]::InvokeGetWebRequest($resourceURL)
            if (([Helpers]::CheckMember($serviceEndpointObj, "count") -and $serviceEndpointObj[0].count -gt 0) -or (($serviceEndpointObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($serviceEndpointObj[0], "name"))) {
                $projectData['ServiceConnections'] = ($serviceEndpointObj | Measure-Object).Count
            }

            # fetch the agent pools count
            if ($projectData["AgentPools"] -eq -1) {
                $agentPoolsDefnURL = ("https://dev.azure.com/{0}/{1}/_settings/agentqueues?__rt=fps&__ver=2") -f $($organizationName), $projectName;
                $agentPoolsDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsDefnURL);
                if (([Helpers]::CheckMember($agentPoolsDefnsObj, "fps.dataProviders.data") ) -and (($agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider") -and $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues)) {
                    $taskAgentQueues = $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues;
                    $projectData["AgentPools"] = ($taskAgentQueues | Measure-Object).Count
                }
            }

            # fetch the variable groups count
            if ($projectData["VariableGroups"] -eq -1) {
                $variableGroupURL = ("https://dev.azure.com/{0}/{1}/_apis/distributedtask/variablegroups?api-version=6.1-preview.2") -f $($organizationName), $projectId;
                $variableGroupObj = [WebRequestHelper]::InvokeGetWebRequest($variableGroupURL)
                if (([Helpers]::CheckMember($variableGroupObj, "count") -and $variableGroupObj[0].count -gt 0) -or (($variableGroupObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($variableGroupObj[0], "name"))) {
                    $varGroups = $variableGroupObj
                    $projectData["VariableGroups"] = ($varGroups | Measure-Object).Count
                }
            }
        }
        catch {}
        [AIOrgTelemetryHelper]::PublishEvent("Projects resources count", $projectData, @{})
    }

}

