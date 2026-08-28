all : 
	cd src ; make

clean :
	cd src ; make clean

help :
	@echo "Usage :"
	@echo " make [all]\t\tBuild the software"
	@echo " make help\t\tDisplay this help"
	@echo " make clean\t\tDestroy Build Files"