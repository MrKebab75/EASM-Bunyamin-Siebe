import sys
sys.path.insert(0, './webappanalyzer')

from webappanalyzer.analyzer import Analyzer

analyzer = Analyzer()
results = analyzer.analyze("http://nwg.se")
print(results)
