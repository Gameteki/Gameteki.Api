node {
    stage('Checkout git repo') {
        checkout scm
    }

    stage('build') {
        sh(script: "dotnet restore", returnStdout: true)
        sh(script: "dotnet build -c Release", returnStdout: true)
    }

    stage('tests') {
        sh(script: "dotnet test -c Release --no-build", returnStdout: true, failOnError: true)
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