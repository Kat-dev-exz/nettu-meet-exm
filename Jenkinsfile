pipeline {
    agent any
    environment {
         DODJO_URL="https://s410-exam.cyber-ed.space:8083/api/v2/import-scan/"
         DODJO_TOKEN="c5b50032ffd2e0aa02e2ff56ac23f0e350af75b4"
         SEMGREP_REPORT = 'report_semgrep.json'
         SEMGREP_MAX_ERROR="5"
         ZAP_MAX_ERROR="5"
        
     }
    
    stages{  
        stage('SAST') {
            steps{
                sh '''
                apk add python3
                apk add --update pipx
                pipx install semgrep; pipx ensurepath; source ~/.bashrc
                /root/.local/bin/semgrep scan --config auto --json > report_semgrep.json
                '''
                stash name: 'report_semgrep', includes: 'report_semgrep.json'
                archiveArtifacts artifacts: 'report_semgrep.json', allowEmptyArchive: true
            }
        }
        
        stage('DAST') {
            agent {
                label 'alpine'
            }    
            steps {
                sh 'curl -L -o ZAP_2.15.0_Linux.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz'
                sh 'tar -xzf ZAP_2.15.0_Linux.tar.gz'
                sh './ZAP_2.15.0/zap.sh -cmd -addonupdate -addoninstall wappalyzer -addoninstall pscanrulesBeta'
                sh 'ls -lt'            
                sh './ZAP_2.15.0/zap.sh -cmd -quickurl https://s410-exam.cyber-ed.space:8082 -quickout $(pwd)/report_zap.xml'
                sh 'ls -lt'
                stash name: 'report_zap', includes: 'report_zap.xml'
                archiveArtifacts artifacts: 'report_zap.xml', allowEmptyArchive: true         
            }           
        }
        
        /*stage('Trivy') {
            agent { label "dind" }
            steps {
                script {
                    sh '''
                    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
                    echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
                    sudo apt update
                    sudo apt install -y trivy
                    mkdir -p reports
                    cd server
                    trivy fs --format cyclonedx -o ../reports/sbom.json package-lock.json
                    trivy sbom -f json -o ../reports/trivy.json ../reports/sbom.json
                    '''
                    archiveArtifacts artifacts: 'reports/*', allowEmptyArchive: true
                    stash includes: 'reports/sbom.json', name: 'sbom'
                    stash includes: 'reports/trivy.json', name: 'trivy-report'
                }
            }
        }
        stage('Dep_Track') {
            agent { label "dind" }
            steps {
                unstash 'sbom'
                script {
                    sh '''
                    ls -l reports/sbom.json
                    response_code=$(curl -v -k --silent --output /dev/null --write-out "%{http_code}" \
                    -X POST "https://s410-exam.cyber-ed.space:8081/api/v1/bom" \
                    -H "Content-Type: multipart/form-data" \
                    -H "X-Api-Key: odt_SfCq7Csub3peq7Y6lSlQy5Ngp9sSYpJl" \
                    -F "autoCreate=true" \
                    -F "projectName=kat2" \
                    -F "projectVersion=1.0" \
                    -F "bom=@reports/sbom.json")
                    echo "Response Code: $response_code"
                    '''
                }
            }
        }

        stage('Qualtity gates') {
            agent {
                label 'alpine'
            }

            steps {
                unstash 'report_semgrep'
                unstash 'report_zap'

                script {
                    def xmlFileContent = readFile 'report_zap.xml'
                    //<riskdesc>High (Low)</riskdesc>
                    def searchString = "<riskcode>3</riskcode>"
                    def lines = xmlFileContent.split('\n')
                    int zapErrorCount = lines.count { line -> line.contains(searchString) }
                    echo "ZAP total error with risk 3 High: ${zapErrorCount}"
                    if (zapErrorCount > env.SEMGREP_MAX_ERROR.toInteger()) {
                        echo "ZAP QG failed"
                    }
                    def jsonText = readFile env.SEMGREP_REPORT
                    def json = new groovy.json.JsonSlurper().parseText(jsonText)
                    int errorCount = 0
                    json.results.each { r ->
                        if (r.extra.severity == "ERROR") {
                            errorCount+=1;
                        }
                    }
                    echo "SEMGREP error count: ${errorCount}"
                    if (errorCount > env.SEMGREP_MAX_ERROR.toInteger()) {
                        echo "SEMGREP QG failed"
                    }
                }
            }
        }*/
        
        stage('Dodjo') {
            agent {
                label 'alpine'
            }
            steps {
                unstash 'report_semgrep'
                unstash 'report_zap'

                sh '''
                    apk update && apk add --no-cache python3 py3-pip py3-virtualenv
                    python3 -m venv venv
                    . venv/bin/activate
                    pip install requests
                    python -m dodjo ${DODJO_URL} ${DODJO_TOKEN} report_semgrep.json "Semgrep report"
                    python -m dodjo ${DODJO_URL} ${DODJO_TOKEN} report_zap.xml "ZAP scan"
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
