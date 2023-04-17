IMAGE_TAG := quillibrium-ceremony-client

build-docker:
	docker build -t $(IMAGE_TAG) .

bash:
	docker run --rm -it $(IMAGE_TAG) bash

participate: build-docker
	docker run --rm -it -v $(PWD)/vouchers:/vouchers $(IMAGE_TAG) ./ceremony-client "/vouchers/quill-voucher-$(shell date +'%m.%d.%y-%H:%M:%S').hex"

dev:
	docker run --rm -it -v $(PWD):$(PWD) --workdir $(PWD) $(IMAGE_TAG) bash