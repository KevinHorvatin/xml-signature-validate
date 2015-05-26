#!/usr/bin/env coffee

argv = require('yargs')
  .usage('Usage: $0 -c certfilename -x xmlfilename')
  .demand(['x', 'c'])
  .argv

xmlCrypto = require 'xml-crypto'
xpath = xmlCrypto.xpath
xmldom = require 'xmldom'
fs = require 'fs'

certToPEM = (cert) -> 
  cert = cert.match(/.{1,64}/g).join('\n');

  if (cert.indexOf('-BEGIN CERTIFICATE-') == -1)
    cert = "-----BEGIN CERTIFICATE-----\n" + cert;
  if (cert.indexOf('-END CERTIFICATE-') == -1)
    cert = cert + "\n-----END CERTIFICATE-----\n";

  return cert;

validateSig = (fullXml, currentNode, cert) ->
  xpathSigQuery = ".//*[local-name(.)='Signature' and " +
                      "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']"
  signatures = xpath(currentNode, xpathSigQuery)
  # function is expecting to validate exactly one signature, so if we find more or fewer
  # that, reject.
  if (signatures.length != 1)
    console.log 'Expected 1 signature, found '+signatures.length
    return false
  signature = signatures[0].toString()
  sig = new xmlCrypto.SignedXml()
  sig.keyInfoProvider = 
    getKeyInfo: (key) ->
      console.log 'getKeyInfo...'
      return "<X509Data></X509Data>"
    getKey: (keyInfo)  ->
      console.log 'getKey'
      return certToPEM(cert)

  sig.loadSignature(signature)
  # expect each signature to contain exactly one reference to the top level of the xml we
  # validating, so if we see anything else, reject.
  if (sig.references.length != 1 )
    console.log 'Expected 1 reference, found '+signatures.references.length
    return false
  refUri = sig.references[0].uri
  refId = if (refUri[0] == '#') then refUri.substring(1) else refUri

  # we can't find the reference at the top level, reject
  idAttribute = if currentNode.getAttribute('ID') then 'ID' else 'Id'
  currentId = currentNode.getAttribute idAttribute

  if currentId != refId
    console.log "ID attribute mismatch: #{currentId} != #{refId}"
    return false
  else
    idNode = currentNode

  # we find any extra referenced nodes, reject.  (xml-crypto only verifies one digest, so
  # candidate references is bad news)
  totalReferencedNodes = xpath(idNode.ownerDocument,
                                  "//*[@" + idAttribute + "='" + refId + "']")
  if (totalReferencedNodes.length > 1)
    console.log 'referenced nodes == '+totalReferencedNodes.length
    return false
  
  sig.checkSignature(fullXml)

readOptions = 
  encoding: 'utf8'

xml = fs.readFileSync argv.x, readOptions
cert = fs.readFileSync argv.c, { encoding: 'ascii' }

doc = new xmldom.DOMParser().parseFromString(xml)
assertionQuery = ".//*[local-name(.)='Assertion']"
assertionNode = xpath doc.documentElement, assertionQuery

if doc?
  valid = validateSig xml, assertionNode[0], cert
else
  console.log 'UNABLE to parse XML'

if valid
  console.log 'IS VALID!!'
else
  console.log 'OH NO!'
