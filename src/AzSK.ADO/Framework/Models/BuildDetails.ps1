Set-StrictMode -Version Latest
# This class contains build definition details and check the forked settings.
class BuildDetails
{
   [string] $OrganizationName
   [string] $ProjectName
   [string] $ProjectVisibility
   [System.Collections.Generic.List[ImpactedPipelines]]$ForkBuilds
}

class ImpactedPipelines
{
   [string] $BuildName
   [string] $BuildUrl
   [System.Collections.Generic.List[ForkedBuildSettings]]$ForkedConfigs
}

class ForkedBuildSettings
{
  [bool] $IsCommentRequiredForPullRequest
  [bool] $ForksAllowSecrets
  [bool] $AllowFullAccessToken
  [bool] $ForksEnabled
}