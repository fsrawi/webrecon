pipeline {
    agent any

    environment {
        DOCKER_IMAGE = "webrecon-pro:${env.BUILD_ID}"
    }

    stages {
        stage('1. Checkout Code') {
            steps {
                checkout scm
            }
        }

        stage('2. SAST (Static Analysis)') {
            steps {
                echo "Running Static Application Security Testing..."
                sh 'pip3 install bandit || true'
                sh 'bandit -r . -f html -o bandit-report.html || true'
            }
        }

        stage('3. SCA (Dependencies Check)') {
            steps {
                echo "Scanning open source dependencies..."
                sh 'pip3 install safety || true'
                sh 'safety check -r requirements.txt || true'
            }
        }

        stage('4. Build Docker Image') {
            steps {
                echo "Building Docker Image..."
                sh "docker build -t ${DOCKER_IMAGE} ."
            }
        }

        stage('5. Container Security Scan (Trivy)') {
            steps {
                echo "Scanning Docker image for OS vulnerabilities..."
                sh "trivy image --severity HIGH,CRITICAL ${DOCKER_IMAGE}"
            }
        }

        stage('6. Deploy') {
            steps {
                echo "Deploying the secure container..."
                sh "docker rm -f webrecon_app || true"
                sh "docker run -d -p 80:10000 --name webrecon_app ${DOCKER_IMAGE}"
            }
        }
    }
}
