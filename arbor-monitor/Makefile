DOCKER_REGISTRY := artifactory.cablelabs.com
DOCKER_IMAGE_TAG := test-sp-v10-endpoints
DOCKER_IMAGE_PATH := dis-docker/dis-arbor-monitor:$(DOCKER_IMAGE_TAG)

# This is to save/upload Docker images for participant hosts that can't download images using Docker
DOCKER_SAVE_FILE_GZ := dis-arbor-monitor.$(DOCKER_IMAGE_TAG).gz
DOCKER_UPLOAD_PATH := "https://${DOCKER_REGISTRY}/artifactory/dis-files/com/cablelabs/dis/"

docker-build:
	docker build -t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_PATH) .

docker-push:
	docker login $(DOCKER_REGISTRY)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_PATH)

docker-save:
	docker save $(DOCKER_REGISTRY)/$(DOCKER_IMAGE_PATH) | gzip > $(DOCKER_SAVE_FILE_GZ)
# To restore from a docker save use: gunzip < docker-image.gz | docker load

docker-upload: ${DOCKER_SAVE_FILE_GZ}
	@echo "Note: No progress is provided during the upload process. The upload will just appear to hang until it's complete."
	@curl --user $(shell bash -c 'read -p "Username for ${DOCKER_REGISTRY}: " username; echo $$username') -T ${DOCKER_SAVE_FILE_GZ} ${DOCKER_UPLOAD_PATH}
