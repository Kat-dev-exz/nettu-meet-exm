pipeline {
    agent any
    stages{
        
        /*stage('SAST'){
            steps{
                sh '''
                apk add python3
                apk add --update pipx
                pipx install semgrep; pipx ensurepath; source ~/.bashrc
                /root/.local/bin/semgrep scan --config auto --json > report_semgrep.json
                '''
                archiveArtifacts artifacts: 'report_semgrep.json', allowEmptyArchive: true
            }
        }*/
        
        /*stage('container sec') {
            agent {
                label 'dind'
            }
            steps {
                sh '''
                    cd server
                    docker login -u mummytroll777 -p 7087Taek7
                    docker build . -t Kat-dev-exz/nettu-meet-exm:latest -f Dockerfile
                    docker image ls
                    sudo apt-get install -y curl
                    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
                    ./bin/trivy image --format cyclonedx --output ${WORKSPACE}/sbom.json Kat-dev-exz/nettu-meet-exm:latest
                    cd ${WORKSPACE}
                    ls -lt                    
                '''
                stash name: 'sbom', includes: 'sbom.json'
                archiveArtifacts artifacts: "sbom.json", allowEmptyArchive: true
            }
        }*/
        stage('DAST') {
            agent {
                label 'alpine'
            }    
            steps {
                sh 'curl -L -o ZAP_2.15.0_Linux.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz'
                sh 'tar -xzf ZAP_2.15.0_Linux.tar.gz'
                sh './ZAP_2.15.0/zap.sh -cmd -addonupdate -addoninstall wappalyzer -addoninstall pscanrulesBeta'
                sh 'ls -lt'            
                sh './ZAP_2.15.0/zap.sh -cmd -quickurl https://s410-exam.cyber-ed.space:8082 -quickout $(pwd)/zapsh-report.zml'
                sh 'ls -lt'
                stash name: 'zapsh-report', includes: 'zapsh-report.xml'
                archiveArtifacts artifacts: 'zapsh-report.xml', allowEmptyArchive: true         
            }            
        } 
        stage('SCA'){
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
    }
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
