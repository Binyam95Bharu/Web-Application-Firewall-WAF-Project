# የዌብ አፕሊኬሽን ፋየርዎል (WAF) ፕሮጀክት

ይህ ፕሮጀክት በ Python Flask የተሰራ እና የዌብ አፕሊኬሽኖችን ከተለያዩ የሳይበር ጥቃቶች ለመከላከል የሚያስችል የመማሪያ WAF (Web Application Firewall) ነው። ፕሮጀክቱ ሞዱላር በሆነ መንገድ የተዋቀረ ሲሆን፣ ለ SQL Injection, XSS እና CSRF ጥቃቶች መከላከያዎችን ያካትታል።

## የፕሮጀክቱ ዓላማ

የዚህ ፕሮጀክት ዋና ዓላማ የWAFን አሰራር፣ የጥቃት አይነቶችን እና የመከላከያ ዘዴዎችን በተግባር መረዳት ነው።

## ዋና ዋና ክፍሎች

* **WAF Core (`waf.py`)**: የጥያቄዎችን ትራፊክ የሚፈትሽ እና ህጎችን የሚተገብር ዋናው የWAF ሞጁል።
* **Rules (`rules/`)**: ለእያንዳንዱ የጥቃት አይነት የተለየ ህግ የሚገኝበት ማህደር።
    * `sql_injection.py`: የSQL Injection ጥቃቶችን ለመለየት።
    * `xss.py`: የXSS ጥቃቶችን ለመለየት።
    * `csrf.py`: የCSRF ጥቃቶችን ለመከላከል (የሚጠፋ ቶከን በመፈለግ)።
    * `rate_limiting.py`: የDoS ጥቃቶችን ለመከላከል የጥያቄዎችን ፍጥነት የሚገድብ።
* **Utilities (`utils/`)**: ለፕሮጀክቱ የሚረዱ ተጨማሪ ተግባራትን የያዘ ማህደር።
    * `logger.py`: ለክስተቶች ማስጠንቀቂያ ለመመዝገብ።
    * `config.py`: የWAF ውቅረቶችን ከፋይል እንዲጭን።
* **Tests (`test_*.py`)**: የWAF ህጎች እና ዋናው ኮድ በትክክል እንደሚሰሩ ለማረጋገጥ የሚያገለግሉ ዩኒት ቴስቶች።

## እንዴት ማስኬድ ይቻላል

### ቅድመ ሁኔታዎች (Prerequisites)

ይህን ፕሮጀክት ለመጀመር Python 3 እና Pip መጫን ያስፈልጋል።

### የጥገኛ ላይብረሪዎች (Dependencies) መትከል

```bash
pip install Flask
pip install -r requirements.txt # requirements.txt ከሌለህ Flask ብቻ መጫን ትችላለህ።
