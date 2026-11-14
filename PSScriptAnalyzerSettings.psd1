# PSScriptAnalyzer settings used locally and in CI.
# Write-Host is excluded on purpose: these are interactive console tools that
# print coloured status lines; structured data is still emitted to the pipeline.
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @('PSAvoidUsingWriteHost')
}
