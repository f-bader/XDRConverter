function Test-CustomDetectionMitreTechnique {
    <#
    .SYNOPSIS
        Validates that MITRE ATT&CK techniques in a detection rule are supported by XDR for the selected category.

    .DESCRIPTION
        Reads the alertCategory and mitreTechniques from a detection YAML file or object and checks
        each technique against the set of techniques that Microsoft XDR supports for that category.
        Techniques not supported by XDR for the given category are reported as invalid.

        The technique mapping is derived from the XDR portal's front-end data and reflects the
        actual techniques available in each alert category dropdown.

        Categories not present in the XDR mapping (e.g. SuspiciousActivity) cannot be validated;
        in that case the function emits a warning and returns IsValid = $true with no invalid techniques.

    .PARAMETER InputFile
        Path to a detection YAML (.yaml/.yml) file.

    .PARAMETER InputObject
        A parsed YAML/detection PSObject. Accepts pipeline input.

    .OUTPUTS
        PSCustomObject with:
          IsValid          - $true if all listed techniques are supported for the category
          Category         - the alertCategory value
          ValidTechniques  - techniques that are supported for the category
          InvalidTechniques- techniques that are NOT supported for the category
          IsValid          - $true if all listed techniques are supported for the category
          Category         - the alertCategory value
          ValidTechniques  - techniques that are supported for the category
          InvalidTechniques- techniques that are NOT supported for the category

    .EXAMPLE
        Test-CustomDetectionMitreTechnique -InputFile '.\detection.yaml'

        Validates all MITRE techniques in the YAML file against the XDR category mapping.

    .EXAMPLE
        Get-ChildItem '.\detections\*.yaml' | ForEach-Object { Test-CustomDetectionMitreTechnique -InputFile $_.FullName }

        Validates all YAML files in a directory.

    .EXAMPLE
        Import-CustomDetectionYamlFile -FilePath '.\detection.yaml' | Test-CustomDetectionMitreTechnique

        Pipeline input from a parsed YAML object.

    .EXAMPLE
        $result = Test-CustomDetectionMitreTechnique -InputFile '.\detection.yaml'
        if (-not $result.IsValid) {
            Write-Warning "Unsupported techniques: $($result.InvalidTechniques -join ', ')"
        }
    #>
    [CmdletBinding(DefaultParameterSetName = 'File')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'File', HelpMessage = 'Path to a detection YAML file')]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$InputFile,

        [Parameter(Mandatory, ParameterSetName = 'Object', ValueFromPipeline, HelpMessage = 'Parsed detection object')]
        [ValidateNotNull()]
        [PSObject]$InputObject
    )

    begin {
        # XDR MITRE technique mapping per alert category
        # Source: Microsoft XDR portal front-end (xdr-main.js)
        $xdrTechniqueMap = @{
            DefenseEvasion          = @('T1055.011', 'T1205.002', 'T1066', 'T1027.011', 'T1218.011', 'T1143', 'T1027.009', 'T1150', 'T1556.003', 'T1578.004', 'T1148', 'T1564.012', 'T1222.002', 'T1216.001', 'T1574.007', 'T1006', 'T1666', 'T1564.008', 'T1027.013', 'T1014', 'T1109', 'T1036.007', 'T1548.002', 'T1099', 'T1548.003', 'T1578', 'T1542.001', 'T1574.011', 'T1542.003', 'T1116', 'T1218.013', 'T1093', 'T1036.005', 'T1600', 'T1036.008', 'T1121', 'T1564', 'T1484.002', 'T1527', 'T1562.009', 'T1542.005', 'T1497.001', 'T1070.002', 'T1218.004', 'T1089', 'T1027.008', 'T1574.001', 'T1553.001', 'T1553.002', 'T1036.009', 'T1222.001', 'T1574.014', 'T1218.007', 'T1556.002', 'T1070.007', 'T1600.001', 'T1070.003', 'T1202', 'T1536', 'T1140', 'T1562', 'T1055.003', 'T1036', 'T1070.008', 'T1055', 'T1205', 'T1218', 'T1038', 'T1070.006', 'T1620', 'T1480.002', 'T1564.011', 'T1497.003', 'T1218.003', 'T1562.002', 'T1218.002', 'T1599.001', 'T1036.011', 'T1009', 'T1550', 'T1181', 'T1562.004', 'T1152', 'T1553.003', 'T1556.007', 'T1218.015', 'T1562.012', 'T1207', 'T1553.006', 'T1610', 'T1107', 'T1112', 'T1574.008', 'T1535', 'T1564.013', 'T1027.001', 'T1484.001', 'T1078.001', 'T1183', 'T1085', 'T1574.006', 'T1070.001', 'T1222', 'T1027.016', 'T1548', 'T1134.002', 'T1548.001', 'T1117', 'T1054', 'T1108', 'T1218.008', 'T1548.005', 'T1144', 'T1045', 'T1055.013', 'T1578.003', 'T1574.005', 'T1198', 'T1562.006', 'T1564.014', 'T1562.007', 'T1036.002', 'T1027.017', 'T1542.002', 'T1070', 'T1550.003', 'T1036.004', 'T1055.004', 'T1647', 'T1127.003', 'T1191', 'T1553.005', 'T1600.002', 'T1542', 'T1064', 'T1612', 'T1055.002', 'T1218.012', 'T1562.010', 'T1497', 'T1218.005', 'T1480', 'T1134.001', 'T1205.001', 'T1027.012', 'T1564.002', 'T1134.003', 'T1196', 'T1562.003', 'T1556.008', 'T1497.002', 'T1134.004', 'T1055.014', 'T1122', 'T1502', 'T1574.010', 'T1149', 'T1170', 'T1574.013', 'T1542.004', 'T1218.001', 'T1070.005', 'T1562.001', 'T1601', 'T1574', 'T1027.005', 'T1078', 'T1073', 'T1055.012', 'T1564.009', 'T1027', 'T1556.006', 'T1036.001', 'T1564.006', 'T1027.014', 'T1134.005', 'T1599', 'T1553', 'T1548.004', 'T1218.010', 'T1036.003', 'T1562.011', 'T1574.009', 'T1186', 'T1027.003', 'T1550.004', 'T1078.002', 'T1218.009', 'T1506', 'T1553.004', 'T1027.004', 'T1564.007', 'T1197', 'T1127.001', 'T1656', 'T1578.005', 'T1088', 'T1562.008', 'T1564.003', 'T1127.002', 'T1070.010', 'T1147', 'T1556.009', 'T1578.002', 'T1500', 'T1055.009', 'T1223', 'T1601.001', 'T1070.009', 'T1146', 'T1036.010', 'T1556.001', 'T1027.006', 'T1556.005', 'T1027.010', 'T1130', 'T1070.004', 'T1158', 'T1221', 'T1134', 'T1027.002', 'T1564.005', 'T1672', 'T1151', 'T1055.005', 'T1622', 'T1036.006', 'T1550.002', 'T1574.002', 'T1216.002', 'T1126', 'T1548.006', 'T1055.008', 'T1027.007', 'T1055.015', 'T1484', 'T1220', 'T1564.001', 'T1578.001', 'T1550.001', 'T1078.004', 'T1480.001', 'T1564.004', 'T1096', 'T1055.001', 'T1556', 'T1216', 'T1118', 'T1556.004', 'T1027.015', 'T1574.004', 'T1601.002', 'T1078.003', 'T1211', 'T1127', 'T1218.014', 'T1564.010', 'T1574.012')
            PrivilegeEscalation     = @('T1055.011', 'T1053.005', 'T1037', 'T1150', 'T1574.007', 'T1044', 'T1546.013', 'T1514', 'T1543', 'T1546.006', 'T1053.007', 'T1548.002', 'T1548.003', 'T1574.011', 'T1178', 'T1547', 'T1013', 'T1206', 'T1547.014', 'T1484.002', 'T1543.003', 'T1053.003', 'T1165', 'T1098.003', 'T1547.012', 'T1574.001', 'T1103', 'T1574.014', 'T1098.006', 'T1053', 'T1058', 'T1098.007', 'T1055.003', 'T1546.011', 'T1547.010', 'T1037.002', 'T1055', 'T1038', 'T1050', 'T1611', 'T1547.009', 'T1182', 'T1547.005', 'T1181', 'T1543.004', 'T1574.008', 'T1484.001', 'T1078.001', 'T1547.003', 'T1183', 'T1546.005', 'T1574.006', 'T1053.001', 'T1179', 'T1547.011', 'T1548', 'T1134.002', 'T1548.001', 'T1547.004', 'T1098.004', 'T1546.012', 'T1548.005', 'T1055.013', 'T1574.005', 'T1546.008', 'T1504', 'T1055.004', 'T1138', 'T1546.009', 'T1098.005', 'T1055.002', 'T1547.015', 'T1134.001', 'T1098.001', 'T1134.003', 'T1053.004', 'T1546.003', 'T1134.004', 'T1546.001', 'T1055.014', 'T1015', 'T1546.014', 'T1502', 'T1169', 'T1574.010', 'T1547.001', 'T1098', 'T1547.006', 'T1574.013', 'T1053.006', 'T1157', 'T1574', 'T1543.005', 'T1078', 'T1055.012', 'T1068', 'T1546', 'T1546.004', 'T1134.005', 'T1548.004', 'T1547.002', 'T1546.015', 'T1574.009', 'T1166', 'T1037.005', 'T1100', 'T1078.002', 'T1034', 'T1037.003', 'T1088', 'T1546.010', 'T1546.002', 'T1543.001', 'T1055.009', 'T1519', 'T1546.016', 'T1037.004', 'T1134', 'T1543.002', 'T1547.013', 'T1055.005', 'T1547.007', 'T1574.002', 'T1098.002', 'T1548.006', 'T1160', 'T1055.008', 'T1037.001', 'T1055.015', 'T1484', 'T1547.008', 'T1078.004', 'T1053.002', 'T1055.001', 'T1546.017', 'T1546.007', 'T1574.004', 'T1078.003', 'T1574.012', 'T0874', 'T0890')
            Execution               = @('T1053.005', 'T1047', 'T1129', 'T1059.007', 'T1053.007', 'T1121', 'T1559.002', 'T1204.002', 'T1053.003', 'T1559.001', 'T1675', 'T1053', 'T1059.002', 'T1106', 'T1059.010', 'T1153', 'T1569.003', 'T1152', 'T1059.009', 'T1610', 'T1155', 'T1085', 'T1674', 'T1053.001', 'T1117', 'T1177', 'T1059', 'T1175', 'T1609', 'T1191', 'T1064', 'T1569.001', 'T1059.008', 'T1559.003', 'T1204', 'T1196', 'T1053.004', 'T1072', 'T1059.001', 'T1170', 'T1053.006', 'T1061', 'T1059.004', 'T1559', 'T1059.011', 'T1204.003', 'T1154', 'T1203', 'T1168', 'T1028', 'T1059.006', 'T1569', 'T1059.003', 'T1223', 'T1059.012', 'T1651', 'T1059.005', 'T1204.004', 'T1151', 'T1648', 'T1173', 'T1204.001', 'T1569.002', 'T1053.002', 'T1035', 'T1086', 'T1118', 'T0821', 'T0807', 'T0863', 'T0858', 'T0853', 'T0871', 'T0895', 'T0875', 'T0874', 'T0844', 'T0823', 'T0834')
            Persistence             = @('T1053.005', 'T1205.002', 'T1156', 'T1067', 'T1037', 'T1161', 'T1150', 'T1556.003', 'T1574.007', 'T1044', 'T1546.013', 'T1501', 'T1543', 'T1133', 'T1109', 'T1546.006', 'T1053.007', 'T1542.001', 'T1574.011', 'T1163', 'T1542.003', 'T1547', 'T1013', 'T1547.014', 'T1176.001', 'T1180', 'T1542.005', 'T1543.003', 'T1053.003', 'T1165', 'T1137', 'T1098.003', 'T1547.012', 'T1574.001', 'T1103', 'T1137.006', 'T1505.002', 'T1574.014', 'T1098.006', 'T1053', 'T1162', 'T1556.002', 'T1505.005', 'T1176', 'T1058', 'T1137.005', 'T1098.007', 'T1546.011', 'T1547.010', 'T1037.002', 'T1205', 'T1038', 'T1050', 'T1547.009', 'T1062', 'T1182', 'T1525', 'T1547.005', 'T1004', 'T1131', 'T1152', 'T1556.007', 'T1112', 'T1543.004', 'T1574.008', 'T1505.003', 'T1078.001', 'T1547.003', 'T1183', 'T1031', 'T1546.005', 'T1574.006', 'T1136.001', 'T1053.001', 'T1176.002', 'T1179', 'T1547.011', 'T1547.004', 'T1019', 'T1042', 'T1164', 'T1108', 'T1098.004', 'T1215', 'T1101', 'T1546.012', 'T1177', 'T1574.005', 'T1546.008', 'T1504', 'T1198', 'T1136.002', 'T1542.002', 'T1137.001', 'T1138', 'T1546.009', 'T1098.005', 'T1542', 'T1547.015', 'T1205.001', 'T1098.001', 'T1053.004', 'T1556.008', 'T1546.003', 'T1060', 'T1554', 'T1023', 'T1546.001', 'T1122', 'T1015', 'T1546.014', 'T1574.010', 'T1547.001', 'T1136.003', 'T1098', 'T1547.006', 'T1574.013', 'T1053.006', 'T1542.004', 'T1137.003', 'T1157', 'T1574', 'T1543.005', 'T1078', 'T1556.006', 'T1505.004', 'T1154', 'T1546', 'T1546.004', 'T1547.002', 'T1128', 'T1546.015', 'T1137.004', 'T1574.009', 'T1168', 'T1166', 'T1037.005', 'T1100', 'T1671', 'T1078.002', 'T1034', 'T1037.003', 'T1197', 'T1546.010', 'T1546.002', 'T1556.009', 'T1543.001', 'T1519', 'T1505', 'T1556.001', 'T1556.005', 'T1546.016', 'T1158', 'T1037.004', 'T1209', 'T1159', 'T1543.002', 'T1668', 'T1136', 'T1547.013', 'T1547.007', 'T1574.002', 'T1098.002', 'T1084', 'T1160', 'T1653', 'T1037.001', 'T1137.002', 'T1547.008', 'T1078.004', 'T1053.002', 'T1556', 'T1546.017', 'T1546.007', 'T1505.006', 'T1505.001', 'T1556.004', 'T1574.004', 'T1078.003', 'T1574.012', 'T0857', 'T0891', 'T0859', 'T0873', 'T0839', 'T0889')
            CommandAndControl       = @('T1205.002', 'T1132.001', 'T1568.002', 'T1071.004', 'T1172', 'T1071.005', 'T1573.001', 'T1568.001', 'T1071', 'T1024', 'T1219', 'T1079', 'T1659', 'T1205', 'T1032', 'T1572', 'T1483', 'T1071.003', 'T1092', 'T1090.002', 'T1090', 'T1219.001', 'T1568', 'T1188', 'T1102', 'T1568.003', 'T1104', 'T1205.001', 'T1026', 'T1071.002', 'T1102.003', 'T1090.003', 'T1219.003', 'T1001', 'T1571', 'T1573', 'T1102.002', 'T1573.002', 'T1095', 'T1001.003', 'T1065', 'T1090.004', 'T1132', 'T1219.002', 'T1132.002', 'T1071.001', 'T1105', 'T1665', 'T1001.002', 'T1008', 'T1090.001', 'T1094', 'T1102.001', 'T1001.001', 'T1043', 'T0884', 'T0869', 'T0885')
            Collection              = @('T1560.001', 'T1113', 'T1557', 'T1056.001', 'T1602', 'T1213.002', 'T1123', 'T1560.003', 'T1114', 'T1025', 'T1074.001', 'T1114.001', 'T1119', 'T1115', 'T1530', 'T1074.002', 'T1005', 'T1560.002', 'T1557.004', 'T1602.002', 'T1560', 'T1185', 'T1557.003', 'T1557.001', 'T1056.003', 'T1125', 'T1213.001', 'T1114.003', 'T1074', 'T1056.002', 'T1039', 'T1114.002', 'T1056', 'T1213.004', 'T1557.002', 'T1213.003', 'T1213', 'T1602.001', 'T1056.004', 'T1213.005', 'T0887', 'T0850', 'T0861', 'T0868', 'T0801', 'T0845', 'T0811', 'T0802', 'T0877', 'T0825', 'T0870', 'T0830', 'T0852', 'T0893')
            LateralMovement         = @('T1021.005', 'T1080', 'T1527', 'T1021.004', 'T1017', 'T1091', 'T1021.008', 'T1563.001', 'T1021.002', 'T1550', 'T1076', 'T1021', 'T1563', 'T1021.006', 'T1021.003', 'T1175', 'T1550.003', 'T1051', 'T1021.007', 'T1072', 'T1210', 'T1534', 'T1097', 'T1570', 'T1184', 'T1075', 'T1028', 'T1550.004', 'T1506', 'T1563.002', 'T1550.002', 'T1021.001', 'T1550.001', 'T1077', 'T0866', 'T0812', 'T0844', 'T0843', 'T0891', 'T0859', 'T0886', 'T0867')
            CredentialAccess        = @('T1557', 'T1556.003', 'T1056.001', 'T1110.001', 'T1003', 'T1171', 'T1539', 'T1003.002', 'T1552.005', 'T1555.002', 'T1522', 'T1110.002', 'T1555.001', 'T1003.004', 'T1606.002', 'T1167', 'T1214', 'T1003.007', 'T1555.005', 'T1040', 'T1552.002', 'T1556.002', 'T1558.005', 'T1558.004', 'T1558', 'T1555', 'T1552', 'T1139', 'T1503', 'T1557.004', 'T1556.007', 'T1145', 'T1555.003', 'T1557.003', 'T1552.004', 'T1557.001', 'T1003.001', 'T1179', 'T1110.003', 'T1056.003', 'T1003.005', 'T1558.001', 'T1649', 'T1552.003', 'T1552.001', 'T1606.001', 'T1528', 'T1552.006', 'T1556.008', 'T1141', 'T1606', 'T1621', 'T1552.008', 'T1212', 'T1142', 'T1056.002', 'T1110', 'T1110.004', 'T1208', 'T1556.006', 'T1187', 'T1174', 'T1081', 'T1056', 'T1557.002', 'T1556.009', 'T1555.006', 'T1003.008', 'T1558.002', 'T1555.004', 'T1556.001', 'T1556.005', 'T1111', 'T1003.003', 'T1558.003', 'T1003.006', 'T1556', 'T1056.004', 'T1552.007', 'T1556.004')
            Discovery               = @('T1033', 'T1613', 'T1016.001', 'T1069', 'T1069.003', 'T1615', 'T1652', 'T1087.002', 'T1063', 'T1087.001', 'T1497.001', 'T1069.002', 'T1007', 'T1040', 'T1135', 'T1120', 'T1082', 'T1016.002', 'T1010', 'T1087.003', 'T1497.003', 'T1580', 'T1217', 'T1673', 'T1016', 'T1087', 'T1482', 'T1083', 'T1049', 'T1497', 'T1619', 'T1654', 'T1087.004', 'T1057', 'T1497.002', 'T1069.001', 'T1201', 'T1614.001', 'T1012', 'T1614', 'T1518.001', 'T1526', 'T1018', 'T1046', 'T1518', 'T1538', 'T1622', 'T1124', 'T0887', 'T0888', 'T0842', 'T0841', 'T0854', 'T0808', 'T0846', 'T0824', 'T0840')
            ResourceDevelopment     = @('T1583', 'T1583.007', 'T1588.007', 'T1584.008', 'T1583.008', 'T1588.004', 'T1583.002', 'T1587.003', 'T1587.001', 'T1586.001', 'T1588.006', 'T1583.005', 'T1608.004', 'T1587.002', 'T1584.003', 'T1586.003', 'T1586.002', 'T1608.001', 'T1583.001', 'T1608.002', 'T1583.004', 'T1585.002', 'T1588.001', 'T1583.003', 'T1584', 'T1586', 'T1584.005', 'T1608', 'T1608.005', 'T1583.006', 'T1585.003', 'T1588.002', 'T1584.006', 'T1585.001', 'T1587.004', 'T1608.003', 'T1584.002', 'T1585', 'T1588', 'T1650', 'T1584.007', 'T1584.004', 'T1608.006', 'T1588.003', 'T1587', 'T1588.005', 'T1584.001')
            Reconnaissance          = @('T1592', 'T1596.003', 'T1597.002', 'T1590.005', 'T1590.002', 'T1596.002', 'T1594', 'T1596.001', 'T1591.003', 'T1592.001', 'T1598.003', 'T1590.004', 'T1590.003', 'T1597.001', 'T1589', 'T1595.002', 'T1596', 'T1595', 'T1589.002', 'T1598.004', 'T1590.006', 'T1593.002', 'T1591.002', 'T1593.003', 'T1589.003', 'T1592.004', 'T1598.002', 'T1596.004', 'T1591', 'T1590', 'T1593', 'T1597', 'T1592.003', 'T1592.002', 'T1593.001', 'T1589.001', 'T1595.003', 'T1591.004', 'T1598', 'T1595.001', 'T1590.001', 'T1596.005', 'T1591.001', 'T1598.001')
            Impact                  = @('T1561.002', 'T1498.001', 'T1492', 'T1491.002', 'T1499.001', 'T1485.001', 'T1496.003', 'T1499.003', 'T1561', 'T1565.001', 'T1489', 'T1499.004', 'T1487', 'T1565.003', 'T1498.002', 'T1499.002', 'T1491', 'T1496.002', 'T1657', 'T1491.001', 'T1496.004', 'T1496.001', 'T1565', 'T1531', 'T1486', 'T1488', 'T1667', 'T1499', 'T1494', 'T1493', 'T1496', 'T1565.002', 'T1485', 'T1498', 'T1495', 'T1490', 'T1561.001', 'T1529', 'T0829', 'T0831', 'T0837', 'T0832', 'T0815', 'T0880', 'T0828', 'T0879', 'T0827', 'T0826', 'T0882', 'T0813')
            InitialAccess           = @('T1133', 'T1195.001', 'T1192', 'T1566.002', 'T1566.001', 'T1195.003', 'T1091', 'T1195', 'T1190', 'T1659', 'T1078.001', 'T1193', 'T1199', 'T1566', 'T1078', 'T1566.004', 'T1195.002', 'T1078.002', 'T1194', 'T1200', 'T1189', 'T1078.004', 'T1566.003', 'T1078.003', 'T1669', 'T0860', 'T0819', 'T0864', 'T0810', 'T0862', 'T0865', 'T0817', 'T0866', 'T0822', 'T0848', 'T0847', 'T0818', 'T0886', 'T0883')
            Exfiltration            = @('T1567', 'T1567.004', 'T1029', 'T1011', 'T1011.001', 'T1020', 'T1048.001', 'T1020.001', 'T1567.001', 'T1048.002', 'T1041', 'T1048', 'T1052.001', 'T1002', 'T1567.003', 'T1567.002', 'T1030', 'T1537', 'T1022', 'T1052', 'T1048.003')
            InhibitResponseFunction = @('T0803', 'T0881', 'T0800', 'T0814', 'T0805', 'T0816', 'T0878', 'T0835', 'T0851', 'T0804', 'T0809', 'T0857', 'T0833', 'T0838', 'T0892')
            ImpairProcessControl    = @('T0836', 'T0855', 'T0856', 'T0806', 'T0875', 'T0833', 'T0839')
            Evasion                 = @('T0894', 'T0858', 'T0851', 'T0872', 'T0856', 'T0820', 'T0849')
        }
    }

    process {
        try {
            $yamlObj = if ($PSCmdlet.ParameterSetName -eq 'File') {
                Import-CustomDetectionYamlFile -FilePath $InputFile
            } else {
                $InputObject
            }

            $category = $yamlObj.alertCategory
            $techniques = $yamlObj.mitreTechniques

            if (-not $category) {
                throw "The detection object does not contain an 'alertCategory' property."
            }

            # No techniques defined — nothing to validate
            if (-not $techniques -or $techniques.Count -eq 0) {
                Write-Verbose "No mitreTechniques defined in the detection. Nothing to validate."
                return [PSCustomObject]@{
                    IsValid           = $true
                    Category          = $category
                    ValidTechniques   = @()
                    InvalidTechniques = @()
                }
            }

            # Category not present in XDR mapping — cannot validate
            if (-not $xdrTechniqueMap.ContainsKey($category)) {
                Write-Warning "Category '$category' is not present in the XDR technique mapping. Validation skipped."
                return [PSCustomObject]@{
                    IsValid           = $true
                    Category          = $category
                    ValidTechniques   = @($techniques)
                    InvalidTechniques = @()
                }
            }

            $supported = $xdrTechniqueMap[$category]
            $supportedSet = [System.Collections.Generic.HashSet[string]]::new($supported, [System.StringComparer]::OrdinalIgnoreCase)

            $validTechniques = [System.Collections.Generic.List[string]]::new()
            $invalidTechniques = [System.Collections.Generic.List[string]]::new()

            foreach ($technique in $techniques) {
                if ($supportedSet.Contains($technique)) {
                    $validTechniques.Add($technique)
                } else {
                    $invalidTechniques.Add($technique)
                }
            }

            $isValid = $invalidTechniques.Count -eq 0

            if (-not $isValid) {
                $invalidList = $invalidTechniques -join ', '
                Write-Warning "The following MITRE technique(s) are not supported by XDR for category '$category': $invalidList"
            }

            [PSCustomObject]@{
                IsValid           = $isValid
                Category          = $category
                ValidTechniques   = $validTechniques.ToArray()
                InvalidTechniques = $invalidTechniques.ToArray()
            }
        } catch {
            Write-Error "Error validating MITRE techniques: $_"
            throw
        }
    }
}
