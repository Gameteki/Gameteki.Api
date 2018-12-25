node {
    stage('Checkout git repo') {
        checkout scm
    }

    stage('Build, Test and Sonar Qube') {
        sh(script: "dotnet restore", returnStdout: true)
        withSonarQubeEnv('Local Sonar') {
            sh(script: "dotnet sonarscanner begin /k:Gameteki.Api /d:sonar.host.url=${SONAR_HOST_URL} /d:sonar.login=${SONAR_AUTH_TOKEN} /d:sonar.cs.opencover.reportsPaths=coverage.opencover.xml", returnStdout: true)
            sh(script: "dotnet build -c Release", returnStdout: true)
            sh(script: "coverlet CrimsonDev.Gameteki.Api.Tests/bin/Release/netcoreapp2.2/CrimsonDev.Gameteki.Api.Tests.dll --target 'dotnet' --targetargs 'test CrimsonDev.Gameteki.Api.Tests/CrimsonDev.Gameteki.Api.Tests.csproj --no-build' --format opencover", returnStdout: true)
            sh(script: "dotnet sonarscanner end /d:sonar.login=${SONAR_AUTH_TOKEN}", returnStdout: true)
        }
    }

    stage('package') {
        sh(script: "dotnet pack -c Release /p:Version=1.0.0.${BUILD_NUMBER} --include-symbols -p:SymbolPackageFormat=snupkg", returnStdout: true)
    }

    stage('deploy') {
        withCredentials([string(credentialsId: 'nuget_apikey', variable: 'NUGET_APIKEY')]) {
            sh(script: "dotnet nuget push bin/Release/CrimsonDev.Gameteki.Api.1.0.0.${BUILD_NUMBER}.nupkg -k ${NUGET_APIKEY} -s https://api.nuget.org/v3/index.json")
        }
    }
}