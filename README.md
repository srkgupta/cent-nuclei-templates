# cent-nuclei-templates
Cent Nuclei Templates generated through the [cent tool](https://github.com/xm1k3/cent)


This repo contains the final list of custom nuclei templates generated from the [cent tool](https://github.com/xm1k3/cent)

Note:
- All the invalid templates which are not compatible with the latest nuclei are removed.
- All the duplicate templates are removed
- All the workflows are removed

### How to run these templates

- Clone the repository:
```
git clone https://github.com/srkgupta/cent-nuclei-templates.git
```

- Run the nuclei templates:
```
nuclei -u https://example.com -t ./cent-nuclei-templates/templates -tags cve
nuclei -l urls.txt -t ./cent-nuclei-templates/templates -tags cve
```
