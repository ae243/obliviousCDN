BIBTEX := bibtex

SOURCES= sigproc.bib *.tex

all: paper paper-alt

paper paper-alt: Makefile $(SOURCES) 
	pdflatex $@
	bibtex --min-crossrefs=100 $@
	pdflatex $@
	pdflatex  $@

clean:
	rm -f *.aux *.log *.out *.bbl *.blg *~ *.bak $(FIGS) $(TARGET).ps $(TARGET).pdf
