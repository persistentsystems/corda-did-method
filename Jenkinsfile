pipeline {

    options {
        gitLabConnection("GitLab_corda_did_method")
    }

    agent {
        docker {
            image 'gradle:jdk8-slim'
            label 'corda_did_method'
            args '-v /root/corda_did_method:/home/gradle/.gradle'

        }
    }

    stages {

        stage('clean') {
            steps {
                sh "./gradlew clean"
            }

        }
        stage('build') {

            steps {

                sh "./gradlew build"
            }
        }
        stage('test') {

            steps {

                sh "./gradlew test"
            }
        }
    }
}
