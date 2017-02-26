
draft-irtf-icnrg-ccnxmessages-00.xml: draft-irtf-icnrg-ccnxmessages.xml
	sed -e 's/draft-irtf-icnrg-ccnxmessages-latest/draft-irtf-icnrg-ccnxmessages-00/' $< > $@
draft-irtf-icnrg-ccnxsemantics-00.xml: draft-irtf-icnrg-ccnxsemantics.xml
	sed -e 's/draft-irtf-icnrg-ccnxsemantics-latest/draft-irtf-icnrg-ccnxsemantics-00/' $< > $@
draft-mosko-icnrg-beginendfragment-00.xml: draft-mosko-icnrg-beginendfragment.xml
	sed -e 's/draft-mosko-icnrg-beginendfragment-latest/draft-mosko-icnrg-beginendfragment-00/' $< > $@
draft-mosko-icnrg-cachecontrol-00.xml: draft-mosko-icnrg-cachecontrol.xml
	sed -e 's/draft-mosko-icnrg-cachecontrol-latest/draft-mosko-icnrg-cachecontrol-00/' $< > $@
draft-mosko-icnrg-ccnxchunking-00.xml: draft-mosko-icnrg-ccnxchunking.xml
	sed -e 's/draft-mosko-icnrg-ccnxchunking-latest/draft-mosko-icnrg-ccnxchunking-00/' $< > $@
draft-mosko-icnrg-ccnxuri-00.xml: draft-mosko-icnrg-ccnxuri.xml
	sed -e 's/draft-mosko-icnrg-ccnxuri-latest/draft-mosko-icnrg-ccnxuri-00/' $< > $@
draft-tschudin-icnrg-flic-00.xml: draft-tschudin-icnrg-flic.xml
	sed -e 's/draft-tschudin-icnrg-flic-latest/draft-tschudin-icnrg-flic-00/' $< > $@
draft-wood-icnrg-ccnxkeyexchange-00.xml: draft-wood-icnrg-ccnxkeyexchange.xml
	sed -e 's/draft-wood-icnrg-ccnxkeyexchange-latest/draft-wood-icnrg-ccnxkeyexchange-00/' $< > $@
draft-wood-icnrg-clean-00.xml: draft-wood-icnrg-clean.xml
	sed -e 's/draft-wood-icnrg-clean-latest/draft-wood-icnrg-clean-00/' $< > $@
draft-wood-icnrg-esic-00.xml: draft-wood-icnrg-esic.xml
	sed -e 's/draft-wood-icnrg-esic-latest/draft-wood-icnrg-esic-00/' $< > $@
diff-draft-wood-icnrg-esic-.txt.html: draft-wood-icnrg-esic-.txt draft-wood-icnrg-esic.txt
	-$(rfcdiff) --html --stdout $^ > $@
diff-draft-wood-icnrg-clean-.txt.html: draft-wood-icnrg-clean-.txt draft-wood-icnrg-clean.txt
	-$(rfcdiff) --html --stdout $^ > $@
diff-draft-wood-icnrg-ccnxkeyexchange-.txt.html: draft-wood-icnrg-ccnxkeyexchange-.txt draft-wood-icnrg-ccnxkeyexchange.txt
	-$(rfcdiff) --html --stdout $^ > $@
diff-draft-tschudin-icnrg-flic-.txt.html: draft-tschudin-icnrg-flic-.txt draft-tschudin-icnrg-flic.txt
	-$(rfcdiff) --html --stdout $^ > $@
diff-draft-mosko-icnrg-ccnxuri-.txt.html: draft-mosko-icnrg-ccnxuri-.txt draft-mosko-icnrg-ccnxuri.txt
	-$(rfcdiff) --html --stdout $^ > $@
diff-draft-mosko-icnrg-ccnxchunking-.txt.html: draft-mosko-icnrg-ccnxchunking-.txt draft-mosko-icnrg-ccnxchunking.txt
	-$(rfcdiff) --html --stdout $^ > $@
diff-draft-mosko-icnrg-cachecontrol-.txt.html: draft-mosko-icnrg-cachecontrol-.txt draft-mosko-icnrg-cachecontrol.txt
	-$(rfcdiff) --html --stdout $^ > $@
diff-draft-mosko-icnrg-beginendfragment-.txt.html: draft-mosko-icnrg-beginendfragment-.txt draft-mosko-icnrg-beginendfragment.txt
	-$(rfcdiff) --html --stdout $^ > $@
diff-draft-irtf-icnrg-ccnxsemantics-.txt.html: draft-irtf-icnrg-ccnxsemantics-.txt draft-irtf-icnrg-ccnxsemantics.txt
	-$(rfcdiff) --html --stdout $^ > $@
diff-draft-irtf-icnrg-ccnxmessages-.txt.html: draft-irtf-icnrg-ccnxmessages-.txt draft-irtf-icnrg-ccnxmessages.txt
	-$(rfcdiff) --html --stdout $^ > $@
