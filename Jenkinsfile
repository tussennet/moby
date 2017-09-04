pipeline {
  agent { label 'freebsd' }
  stages {
    stage('Build') {
      steps {
        sh 'AUTO_GOPATH=1 ./hack/make.sh binary'
      }
    }
  }
}
