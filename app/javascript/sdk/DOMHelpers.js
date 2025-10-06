/**
 * DOMHelpers
 * 
 * CSP Nonce Support:
 * To enable Content Security Policy (CSP) nonce for the Chatwoot widget,
 * add a script tag with id="csp_nonce" containing the nonce value as JSON:
 * 
 * Example:
 *   <script id="csp_nonce" type="application/json">"YOUR_NONCE_VALUE"</script>
 * 
 * The widget will automatically apply this nonce to dynamically injected style tags.
 */

import { IFrameHelper } from './IFrameHelper';
import { SDK_CSS } from './sdk.js';

const getJSON = elementID => {
  const el = document.getElementById(elementID);
  if (el) {
    try {
      return JSON.parse(el.textContent);
    } catch (error) {
      console.warn(`Failed to parse JSON from element ${elementID}:`, error);
      return null;
    }
  }
  return null;
};

const getCspNonce = () => {
  const cspNonce = getJSON('csp_nonce');
  return cspNonce;
};

export const loadCSS = () => {
  const css = document.createElement('style');
  css.innerHTML = `${SDK_CSS}`;
  css.id = 'cw-widget-styles';
  css.dataset.turboPermanent = true;
  
  // Apply CSP nonce if available
  const nonce = getCspNonce();
  if (nonce) {
    css.setAttribute('nonce', nonce);
  }
  
  document.body.appendChild(css);
};

// This is a method specific to Turbo
// The body replacing strategy removes Chatwoot styles
// as well as the widget, this help us get it back
export const restoreElement = (id, newBody) => {
  const element = document.getElementById(id);
  const newElement = newBody.querySelector(`#${id}`);

  if (element && !newElement) {
    newBody.appendChild(element);
  }
};

export const restoreWidgetInDOM = newBody => {
  restoreElement('cw-bubble-holder', newBody);
  restoreElement('cw-widget-holder', newBody);
  restoreElement('cw-widget-styles', newBody);
};

export const addClasses = (elm, classes) => {
  elm.classList.add(...classes.split(' '));
};

export const toggleClass = (elm, classes) => {
  elm.classList.toggle(classes);
};

export const removeClasses = (elm, classes) => {
  elm.classList.remove(...classes.split(' '));
};

export const onLocationChange = ({ referrerURL, referrerHost }) => {
  IFrameHelper.events.onLocationChange({
    referrerURL,
    referrerHost,
  });
};

export const onLocationChangeListener = () => {
  let oldHref = document.location.href;
  const referrerHost = document.location.host;
  const config = {
    childList: true,
    subtree: true,
  };
  onLocationChange({
    referrerURL: oldHref,
    referrerHost,
  });

  const bodyList = document.querySelector('body');
  const observer = new MutationObserver(mutations => {
    mutations.forEach(() => {
      if (oldHref !== document.location.href) {
        oldHref = document.location.href;
        onLocationChange({
          referrerURL: oldHref,
          referrerHost,
        });
      }
    });
  });

  observer.observe(bodyList, config);
};
