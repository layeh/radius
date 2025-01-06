OS?=
CMD_BUILD=GOOS=${OS} go build 
VENDORS=huawei zte

dictgen: cmd/radius-dict-gen/main.go
	${CMD_BUILD} -o $@ $^

define GEN_DICT
  ./vendors/$(1)/generated.go : ./vendors/$(1)/dictionary.$(1)
	./dictgen -output $$@ -package  $(1) $$<
endef

$(foreach v, $(VENDORS), $(eval $(call GEN_DICT,$(v))))

gen: \
	  $(foreach v, $(VENDORS), ./vendors/$(v)/generated.go) 


