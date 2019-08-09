# lambda function attributions
FUNCTION_NAME := lambda-letsencrypt
DESCRIPTION := "Lambda function used to provision letsencrypt certificates"
REGION := us-east-1
ZIP_FILE := lambda-letsencrypt.zip
BUCKET := letsencrypt
BUCKET_DIR := letsencrypt_internal
EMAIL :=
LE_ENV := staging
LAMBDA_ROLE :=
S3_ROLE :=
R53_ROLE :=
ACM_ROLE :=
HANDLER := main.handler
RUNTIME := python3.6
TIMEOUT := 600
MEMORY_SIZE := 192
TAGS :=
ENV_VARS := "{BUCKET=$(BUCKET),BUCKET_DIR=$(BUCKET_DIR),EMAIL=$(EMAIL),LE_ENV=$(LE_ENV),S3_ROLE=$(S3_ROLE),R53_ROLE=$(R53_ROLE),ACM_ROLE=$(ACM_ROLE)}"
CUSTOM_ARGS :=

PKG_FILE := "$(shell pwd)/$(ZIP_FILE)"
REQUIRED_BINS := python3.6 pip3.6

ifneq ($(TAGS),)
CUSTOM_ARGS := $(CUSTOM_ARGS) --tags "$(TAGS)"
endif

.PHONY: dependencies
dependencies:
	$(foreach bin,$(REQUIRED_BINS),\
		$(if $(shell command -v $(bin) 2>/dev/null),$(info Found `$(bin)`),\
			$(error "Could not find `$(bin)` in PATH=$(PATH), consider installing from package manager or from source")))
	( \
		if [ ! -d "./venv" ]; then \
			virtualenv -p python3.6 venv; \
		fi; \
		. venv/bin/activate; \
		pip3.6 install -r requirements.txt; \
		deactivate; \
	)

.PHONY : pack
pack:
	( \
		rm -rf $(PKG_FILE); \
		cd venv/lib/python3.6/site-packages/; \
		zip -r9 ../../../../$(ZIP_FILE) .; \
		cd -; \
		zip -g $(ZIP_FILE) main.py aws.py; \
	)

.PHONY : create-function
create-function:
	test -n "$(EMAIL)" # Empty EMAIL variable
	test -n "$(LAMBDA_ROLE)" # Empty LAMBDA_ROLE variable
	aws lambda create-function \
	--function-name $(FUNCTION_NAME) \
	--description $(DESCRIPTION) \
	--region $(REGION) \
	--zip-file fileb://$(ZIP_FILE) \
	--role $(LAMBDA_ROLE) \
	--handler $(HANDLER) \
	--runtime $(RUNTIME) \
	--timeout $(TIMEOUT) \
	--memory-size $(MEMORY_SIZE) \
	--environment Variables=$(ENV_VARS) $(CUSTOM_ARGS)

.PHONY : update-function
update-function:
	aws lambda update-function-code --function-name $(FUNCTION_NAME) --zip-file fileb://$(ZIP_FILE) --region $(REGION)

.PHONY: deploy
deploy: dependencies pack update-function
