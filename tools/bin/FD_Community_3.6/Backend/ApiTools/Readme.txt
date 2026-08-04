Setup
======
1. Open new Powershell session
2. Extend modules environment variable in local session: $env:PSModulePath += ';[ForestDruid path]\Backend\ApiTools'

Using DruidApi Powershell module
====================================
1. Ensure "Setup" steps are executed
2. Import Powershell cmdlets: Import-Module DruidApi
3. Specify backend endpoint and access token (Required for Powershell version < 7.5.1)
   - Set-DruidBackend -Endpoint 'http://localhost:5000' -AccessToken '12345'
4. Query:
   - Show all data within a number of layers from Tier 0: Get-Graph -NumLayers 1
   - Show all layers to Tier 0: Get-Graph -ShowWholeGraph

Query Aditional Attributes Directly From ProtoGraph
================================================
1. Ensure "Setup" steps are executed
2. Open new Powershell session
3. Query:
   - Query by single Oid: Get-ProtoByOid -OIDs S-1-5-21-1573085206-807083734-1241745230-500
   - Query using Oids:
      $oids = @("S-1-5-21-1573085206-807083734-1241745230-1008","S-1-5-21-1573085206-807083734-1241745230-500")
      Get-ProtoByOid -OIDs $oids
   - Query all protobuf objects:
      $all = Get-ProtoAll


