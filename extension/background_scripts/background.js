// NOTE: this is a custom ffjavascript
const {
  extractNope,
  setupCurves,
  fetchRootZSK,
  buildPublicSignals,
  fetchVKs,
} = require('./lib/nope-utils.js');

async function setDefaultIcon() {
  await browser.browserAction.setIcon({
    path: {
      32: 'src/icons8-nope-32.png',
    },
  });
}

async function setCorrectIcon() {
  await browser.browserAction.setIcon({
    path: {
      32: 'src/icons8-correct-32.png',
    },
  });
}

async function setWrongIcon() {
  const r = await browser.browserAction.setIcon({
    path: {
      32: 'src/icons8-wrong-32.png',
    },
  });
}

function addNopeListener(root_zsk, allECurves) {
  async function checkNope(c, nope) {
    const {proof, type, domain} = nope;
    const publicKeyDigest = c.subjectPublicKeyInfoDigest.sha256.slice(0, 43);
    const issuerOrgName = c.issuer.split(',')[1].split('=')[1];
    const validityStart = c.validity.start;
    const publicSignals = await buildPublicSignals(domain, publicKeyDigest, issuerOrgName, validityStart, root_zsk);
    const res = await allECurves[type].verify(proof, publicSignals);
    return res;
  }

  // async because we need to wait for getSecurityInfo()
  async function nopeListener(details) {
    // check if https by looking at url
    if (!details.url.startsWith('https://')) {
      return {cancel: false};
    }
    // get cert chain (we might want to use rawDER later)
    const certs = (
      await browser.webRequest.getSecurityInfo(details.requestId, {
        certificateChain: true,
        rawDER: true,
      })
    ).certificates;
    // loop over certificates
    for (let c of certs) {
      let nope;
      try {
        nope = extractNope(c.rawDER);
      } catch (e) {
        continue;
      }
      if (!nope) {
        console.log('No NOPE Proof Found');
        continue;
      } else {
        console.log('NOPE Proof Found:', nope);
      }
      const res = await checkNope(c, nope);
      if (res) {
        console.log('Congrats! Your connection is NOPE-secure');
        await setCorrectIcon();
        return {cancel: false};
      } else {
        console.log('NOPE verification failed');
        await setWrongIcon();
        return {cancel: true};
      }
    }
    // otherwise we will let the request pass
    const r = await setDefaultIcon();
    return {cancel: false};
  }

  browser.webRequest.onHeadersReceived.addListener(
    nopeListener,
    // this applies to all urls, but only main_frame types
    // main frame is the page itself, prevents us from checking images, etc.
    {urls: ['<all_urls>'], types: ['main_frame']},
    // we need blocking to be able to cancel the request
    ['blocking', 'responseHeaders'],
  );
}

fetchVKs()
  .then(vks => {
    Promise.all([
      fetchRootZSK(),
      setupCurves(vks),
    ]).then(([root_zsk, allECurves]) => addNopeListener(root_zsk, allECurves));
  })
  .catch(error => console.error('Error in processing:', error));
