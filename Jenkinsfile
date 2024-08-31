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
        /*stage('DAST') {
            agent {
                label 'alpine'
            }    
            steps {
                sh 'curl -L -o ZAP_2.15.0_Linux.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz'
                sh 'tar -xzf ZAP_2.15.0_Linux.tar.gz'
                sh './ZAP_2.15.0/zap.sh -cmd -addonupdate -addoninstall wappalyzer -addoninstall pscanrulesBeta'
                sh 'ls -lt'            
                sh './ZAP_2.15.0/zap.sh -cmd -quickurl https://s410-exam.cyber-ed.space:8082 -quickout $(pwd)/zapsh-report.xml'
                sh 'ls -lt'
                stash name: 'zapsh-report', includes: 'zapsh-report.xml'
                archiveArtifacts artifacts: 'zapsh-report.xml', allowEmptyArchive: true         
            }           
        }*/
        
        stage('Container sec') {
            agent any
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
        }

        stage('SCA_DepTrack') {
            agent {
                label 'alpine'
            }

            steps {
                unstash 'sbom'

                sh '''
                    echo ${WORKSPACE}                    
                    ls -lt           
                    apk update && apk add --no-cache jq
                    response=$(curl -k -s -X PUT "https://s410-exam.cyber-ed.space:8081/api/v1/project" \
                        -H "X-Api-Key: odt_SfCq7Csub3peq7Y6lSlQy5Ngp9sSYpJl" \
                        -H "Content-Type: application/json" \
                        -d '{
                            "name": "kat",
                            "version": "1.0.0"
                        }')

                    uuid=$(echo $response | jq -r '.uuid')
                    echo "Project UUID: $uuid"
                    sbomresponse=$(curl -k -o /dev/null -s -w "%{http_code}" -X POST  "https://s410-exam.cyber-ed.space:8081/api/v1/bom" \
                        -H 'Content-Type: multipart/form-data; boundary=__X_BOM__' \
                        -H "X-API-Key: odt_SfCq7Csub3peq7Y6lSlQy5Ngp9sSYpJl" \
                        -F "bom=@sbom.json" -F "project=${uuid}")
                    echo "Result: $sbomresponse"
                    if [ "$sbomresponse" -ne "200" ]; then
                        echo "Error: Failed to upload SBOM"
                        exit 1
                    fi
                    ls -lt                                        
                '''
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
