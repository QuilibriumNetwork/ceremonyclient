IMAGE_TAG := quillibrium-ceremony-client

build-docker:
	docker build -t $(IMAGE_TAG) .

bash:
	docker run --rm -it $(IMAGE_TAG) bash

participate:
	docker run --rm -it $(IMAGE_TAG) ./ceremony-client "quill-voucher-$(shell date +'%y.%m.%d-%H:%M:%S')"

dev:
	docker run --rm -it -v $(PWD):$(PWD) --workdir $(PWD) $(IMAGE_TAG) bash