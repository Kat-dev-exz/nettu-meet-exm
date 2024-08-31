pipeline {
    agent any
    stages{
        stage('SAST'){
            steps{
                sh '''
                apk add python3
                apk add --update pipx
                pipx install semgrep; pipx ensurepath; source ~/.bashrc
                /root/.local/bin/semgrep scan --config auto --json > report_semgrep.json
                '''
                archiveArtifacts artifacts: 'report_semgrep.json', allowEmptyArchive: true
            }
        }
        stage('container sec'){
            agent {
                label 'dind'
            }
            steps{
                sh '''
                docker run -v ./report:/report aquasec/trivy repo https://github.com/Kat-dev-exz/nettu-meet-exm -f json -o /report/report_trivy.json
                '''
                archiveArtifacts artifacts: 'report/report_trivy.json', allowEmptyArchive: true
            }
        }
        stage('DAST'){
            agent {
                label 'dind'
            }
            steps{
                script{
                    sh '''
                    docker run -v \$(pwd)/:/zap/wrk/:rw -t zaproxy/zap-stable zap-baseline.py -I -t https://s410-exam.cyber-ed.space:8082 -J report_zap.json  
                    '''
                    archiveArtifacts artifacts: 'report_zap.json', allowEmptyArchive: true
                }
            }
        }
        /*stage('SCA'){
            steps {
                script{
                    sh '''
                    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
                    syft dir:$(pwd) -o cyclonedx-json > payload.json
                    curl -k -X "PUT" "https://s410-exam.cyber-ed.space:8081/api/v1/bom" \
                    -H 'Content-Type: application/json'\
                    -H 'X-API-Key: odt_SfCq7Csub3peq7Y6lSlQy5Ngp9sSYpJl' \
                    -d @payload.json
                    '''
                    archiveArtifacts artifacts: 'payload.json', allowEmptyArchive: true
                }
            }
        }
    }*/
    post {
        always {
            echo 'Pipeline end.'
        }
        success {
            echo 'Pipeline success!'
        }
        failure {
            echo 'Pipeline failure ;('
        }
    }
}
}
