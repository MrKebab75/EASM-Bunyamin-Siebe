# EASM-Bunyamin-Siebe

## Architectuur van de Oplossing
Dit project is opgezet als een modulaire security scanning suite, waarbij elk script verantwoordelijk is voor een specifiek onderdeel van External Attack Surface Management (EASM). De architectuur maakt stapsgewijze scanning, data verrijking en rapportage mogelijk, met resultaten die worden opgeslagen in gestructureerde JSON-bestanden voor verdere analyse en visualisatie.

- Het centrale startpunt is `main.py`, waarin alle scripts en functionaliteiten samenkomen en van waaruit de volledige workflow kan worden aangestuurd.
- De gebruiker werkt via een grafische gebruikersinterface (GUI); het is dus niet nodig om scripts handmatig via de command line te starten.
- Elk script (in de map `Scripts/`) voert een specifieke scan uit (zoals subdomein-enumeratie, poortscan, certificaatcontrole, enz.).
- Het script `CompleteSecurityScan.py` regelt de volledige workflow, voert alle scans na elkaar uit en beheert de input/output tussen de stappen.
- Resultaten worden opgeslagen in de map `foundData/` (of een aangepaste outputmap), met één bestand per scantype.

- ![Visualisatie van de architectuur]()

## Context van het Project
Deze oplossing is ontwikkeld voor New Wave Group (NWG) om een volledig en geautomatiseerd overzicht te bieden van het externe digitale aanvalsoppervlak van de organisatie. De belangrijkste meerwaarde voor NWG is:

- Geautomatiseerde ontdekking en analyse van domeinen, subdomeinen, open poorten, SSL-certificaten, webtechnologieën en kwetsbaarheden.
- Gecentraliseerde, reproduceerbare en uitbreidbare scanpipeline.
- Gestructureerde output voor integratie met dashboards of verdere security-analyse.
- Vermindert handmatig werk en vergroot de dekking van potentiële aanvalsvectoren.

## Documentatie van de Configuratie

### Code Repository
Alle code is beschikbaar in deze repository. De scripts zijn georganiseerd in de map `Scripts/`, en elk script heeft een eigen README (zie `Scripts/README-*.md`) met uitleg over gebruik, input/output en vereisten. De repository wordt zonder fouten bijgehouden op GitHub.

### Handleiding
- Installeer eerst alle benodigde afhankelijkheden met het commando:
  ```bash
  pip install -r requirements.txt
  ```
- Zorg ervoor dat de externe tool Amass ook geïnstalleerd is:
  - Amass: 
- Start vervolgens de applicatie en de GUI door het script `main.py` uit te voeren:
  ```bash
  python main.py
  ```
- De volledige scan en alle functionaliteiten zijn te bedienen via de grafische gebruikersinterface (GUI). Het is dus niet nodig om scripts handmatig via de command line te starten.
- Voor meer details over configuratie, afhankelijkheden en outputformaten, raadpleeg de README-bestanden in de map `Scripts/`.

## Panopto video
De Panopto video die bij dit project hoort, is te vinden in de map `Visualisatie/` van deze repository.

## Testplan
Voor het testen van deze oplossing zijn de volgende stappen uitgevoerd:

- De scripts en de volledige workflow zijn getest op domeinen van New Wave Group (NWG) en op de samengestelde lijst van domeinen.
- Voor de verschillende onderdelen van de oplossing zijn meerdere softwaretools en libraries getest. De gegenereerde output van deze tools is met elkaar vergeleken om de beste en meest betrouwbare oplossing te selecteren.
- De gegenereerde outputbestanden zijn vergeleken met verwachte resultaten om de juistheid en volledigheid van de scans te controleren.
- Zowel de werking van de GUI als de correcte aansturing van de onderliggende scripts zijn gevalideerd.
- Eventuele fouten of afwijkingen in de output zijn geanalyseerd en waar nodig opgelost.

Hierdoor is vastgesteld dat de oplossing betrouwbaar functioneert voor zowel NWG als de domeinlijsten.

## Reflectie

### Rolverdeling
In het begin van het project was onze rolverdeling niet heel duidelijk, waardoor sommige taken overlapten of minder efficiënt werden opgepakt. Naarmate het project vorderde, hebben we de taken veel beter verdeeld en afgestemd op ieders sterke punten.

- Bunyamin
    - Heeft zich voornamelijk gefocust op de onderdelen certificaten, domeingeldigheid, het darkweb-gedeelte en start Main bestand voor centrale besturing.
- Siebe
    - Heeft zich voornamelijk gefocust op de onderdelen webtechnologieën, de CVE-scanner, de portscans en opzetten GUI.

### Problemen

- Tijdens het scannen van webtechnologieën werden onze requests regelmatig geblokkeerd door de Web Application Firewall (WAF) van verschillende doelwitten. Dit zorgde ervoor dat we niet altijd een volledig en accuraat beeld kregen van de gebruikte technologieën. We hebben dit probleem deels kunnen oplossen door alternatieve technologieën en methodes te gebruiken voor de detectie. Deze alternatieven zijn soms iets minder accuraat, maar bleken in de praktijk de enige werkbare oplossing om toch relevante resultaten te verkrijgen.

- Tijdens het project is het niet gelukt om betrouwbare en relevante data te verzamelen uit het dark web. Ondanks verschillende pogingen en het testen van diverse tools en methodes, bleek het technisch en praktisch niet haalbaar om dark web data op een veilige en reproduceerbare manier te integreren in de oplossing. 

***Onderaan is ons probleem in detail en voorstel voor een mogelijke oplossing te vinden voor het darkweb gedeelte.***

#### Adviesrapport: Betalende Dark Web API

Tijdens de ontwikkeling van onze ASM-tool hebben wij een functionaliteit ingebouwd die het dark web scant op het voorkomen van domeinen (en data hiervan) vanuit de lijst van domeinen. Deze tool heeft als doel om waarschuwingen te geven bij datalekken, identiteitsmisbruik of vermelding van uw organisatie in risicovolle contexten.

Na tests en iteraties merken we echter dat onze zelfgebouwde dark web scraper niet het gewenste kwaliteitsniveau behaalt. Dit komt hoofdzakelijk door:
- **De complexiteit van het dark web:** Informatie is verspreid over duizenden .onion-sites die vaak offline zijn of veranderen.
- **Gebrek aan schaalbare en accurate data:** Het verkrijgen van relevante en actuele informatie vraagt gevorderde kennis en bronnen.
- **Toegang tot betrouwbare dark web databases vereist vaak een goede reputatie of bestaande zakelijke relaties.** Voor veel van deze betaalde API’s is het noodzakelijk dat je als organisatie een zekere reputatie hebt opgebouwd of een screening doorloopt voordat je toegang krijgt tot hun data.

Daarom raden wij het gebruik van bestaande en betrouwbare betaalde API’s aan om deze functionaliteit professioneel, schaalbaar en nauwkeurig in te richten. Hieronder vindt u een overzicht van enkele toonaangevende aanbieders:

**1. DarkOwl Vision API**
- **Voordelen:**
  - Een van de meest uitgebreide databases van dark web-data wereldwijd.
  - Toegang tot historische en realtime data, inclusief marktplaatsen, fora, Telegram, Pastebin en meer.
  - Uitgebreide zoekmogelijkheden op tekst, domein, IP, e-mail, enz.
- **Nadelen:**
  - Prijzig; licenties variëren sterk op basis van gebruiksvolume.
  - Vereist kennis van query-opbouw voor optimale resultaten.

**2. SpyCloud Dark Web Monitoring API**
- **Voordelen:**
  - Realtime toegang tot gelekte credentials en persoonlijke data van gecompromitteerde accounts.
  - Regelmatige updates van miljoenen datalekken.
  - Koppeling met e-mailadressen, domeinen en gebruikersnamen.
- **Nadelen:**
  - Minder geschikt voor open dark web scraping (zoals fora of marktplaatsen).
  - Prijzig voor kleinere bedrijven.

**3. Constella Intelligence API**
- **Voordelen:**
  - Gericht op identiteits- en fraudedetectie.
  - Combineert surface, deep en dark web-informatie.
  - Sterk in monitoring van persoonlijke gegevens.
- **Nadelen:**
  - Minder gericht op technische assets zoals IP’s of domeinen.
  - Data is sterk persoonsgericht (focus op consumenten en werknemers).