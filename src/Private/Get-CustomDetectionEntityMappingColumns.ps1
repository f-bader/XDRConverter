function Get-CustomDetectionEntityMappingColumns {
    <#
    .SYNOPSIS
        Returns the entity mapping collections and their documented columns.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()

    return [ordered]@{
        accounts             = @('aadUserIdColumn', 'dnsDomainColumn', 'nameColumn', 'ntDomainColumn', 'sidColumn', 'upnColumn', 'upnSuffixColumn')
        amazonResources      = @('amazonResourceIdColumn')
        azureResources       = @('resourceIdColumn')
        cloudApplications    = @('appIdColumn', 'nameColumn')
        dns                  = @('domainNameColumn', 'hostIpAddressColumn', 'serverIpColumn')
        files                = @('nameColumn', 'sha1Column', 'sha256Column')
        googleCloudResources = @('fullResourceNameColumn')
        hosts                = @('deviceIdColumn', 'dnsDomainColumn', 'nameColumn', 'netBiosNameColumn', 'ntDomainColumn')
        ips                  = @('addressColumn', 'scopeColumn')
        mailboxes            = @('primaryAddressColumn')
        mailClusters         = @('queryColumn', 'sourceColumn')
        mailMessages         = @('networkMessageIdColumn', 'recipientColumn', 'senderColumn', 'subjectColumn')
        oAuthApplications    = @('oAuthAppIdColumn')
        processes            = @('sha1Column', 'sha256Column')
        registryValues       = @('keyColumn', 'valueNameColumn')
        securityGroups       = @('distinguishedNameColumn', 'objectIdColumn', 'sidColumn')
        urls                 = @('addressColumn')
    }
}
