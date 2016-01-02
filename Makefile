SOURCE_DIR = ./src

.PHONY: build

demo: build
	@echo "---------------------------------------"
	@echo "-------- Starting CAV demo ... --------"
	@echo "---------------------------------------"
	sh demo.sh

build:
	@echo "----------------------------------"
	@echo "-------- Building CAV ... --------"
	@echo "----------------------------------"
	$(MAKE) -C $(SOURCE_DIR)

clean:
	@echo "----------------------------------------------"
	@echo "-------- Cleaning built CAV files ... --------"
	@echo "----------------------------------------------"
	$(MAKE) -C $(SOURCE_DIR) clean
