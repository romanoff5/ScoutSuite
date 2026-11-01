/* M09-B: context-aware report HTML sanitizer for legacy compiled Handlebars output.
 * All cloud/provider report data is untrusted, including ruleset descriptions.
 * Keep this dependency-free so JSON reports work without an HTTP server.
 */
(function (scope) {
    'use strict';

    const ALLOWED_ACTIONS = new Set([
        'showObject', 'updateHash', 'hideList', 'showRowWithItems',
        'findAndShowEC2Object', 'showIAMManagedPolicy', 'showIAMInlinePolicy',
        'showS3Object', 'showMainDashboard', 'hidePopup',
        'showNamespacedResources', 'copyCode', 'toggleVisibility'
    ]);
    const DANGEROUS_TAGS = new Set([
        'script', 'iframe', 'frame', 'frameset', 'object', 'embed', 'applet',
        'base', 'meta', 'link', 'style', 'svg', 'math', 'template', 'noscript'
    ]);
    const URL_ATTRIBUTES = new Set([
        'href', 'src', 'xlink:href', 'poster', 'action', 'formaction'
    ]);

    // Strictly parse string-literal arguments. Never evaluate a javascript: URL.
    // A malicious apostrophe/semicolon, comment, escape or expression fails closed.
    function parseScoutAction(value) {
        if (typeof value !== 'string' || value.length > 4096) return null;
        const match = /^javascript:\s*([A-Za-z][A-Za-z0-9_]*)\s*\(([\s\S]*)\)\s*;?\s*$/i.exec(value);
        if (!match || !ALLOWED_ACTIONS.has(match[1])) return null;
        const input = match[2];
        const args = [];
        let i = 0;
        const tick = String.fromCharCode(96);
        while (i < input.length) {
            while (/\s/.test(input.charAt(i)) && i < input.length) i++;
            if (i === input.length) break;
            const quote = input.charAt(i++);
            if (quote !== "'" && quote !== '"' && quote !== tick) return null;
            let arg = '';
            let closed = false;
            while (i < input.length) {
                const ch = input.charAt(i++);
                if (ch === quote) { closed = true; break; }
                if (ch === '\\' || /[\u0000-\u001f\u007f\u2028\u2029]/.test(ch)) return null;
                arg += ch;
            }
            if (!closed || arg.length > 2048) return null;
            args.push(arg);
            while (i < input.length && /\s/.test(input.charAt(i))) i++;
            if (i < input.length) {
                if (input.charAt(i++) !== ',') return null;
                if (i >= input.length) return null;
            }
            if (args.length > 5) return null;
        }
        return { name: match[1], args: args };
    }

    function allowedHref(value) {
        if (typeof value !== 'string') return false;
        const url = value.trim();
        if (!url || /[\u0000-\u001f\u007f]/.test(url) || url.startsWith('//')) return false;
        return url.startsWith('#') || /^(https?:\/\/|mailto:)/i.test(url) ||
            /^(?:\.\/)?[A-Za-z0-9_./%-]+(?:\?[A-Za-z0-9_=&%.-]*)?$/.test(url);
    }

    function allowedAsset(value) {
        if (typeof value !== 'string' || /[\u0000-\u0020\u007f]/.test(value)) return false;
        const url = value.trim();
        return /^(?:\.\/)?inc-[a-z0-9_-]+\/[a-zA-Z0-9_./%-]+$/.test(url) &&
            !url.split('/').includes('..');
    }

    function setAction(element, action) {
        element.setAttribute('data-scout-action', action.name);
        element.setAttribute('data-scout-args', JSON.stringify(action.args));
        if (element.tagName.toLowerCase() === 'a') element.setAttribute('href', '#');
    }

    function sanitizeReportHTML(markup) {
        if (typeof document === 'undefined') throw new Error('Report sanitizer requires a DOM');
        const template = document.createElement('template');
        template.innerHTML = String(markup);
        const elements = Array.from(template.content.querySelectorAll('*'));
        for (const element of elements) {
            const tag = element.tagName.toLowerCase();
            if (DANGEROUS_TAGS.has(tag)) {
                element.remove();
                continue;
            }
            // Prevent forged action metadata in raw content. Only this sanitizer creates it.
            element.removeAttribute('data-scout-action');
            element.removeAttribute('data-scout-args');
            for (const attribute of Array.from(element.attributes)) {
                const name = attribute.name.toLowerCase();
                const value = attribute.value;
                if (name.startsWith('on')) {
                    if (name === 'onclick' && (tag === 'a' || tag === 'button')) {
                        const action = parseScoutAction('javascript:' + value);
                        if (action) setAction(element, action);
                    }
                    element.removeAttribute(attribute.name);
                    continue;
                }
                if (name === 'srcdoc' || name === 'srcset') {
                    element.removeAttribute(attribute.name);
                    continue;
                }
                if (name === 'style' && /(?:url\s*\(|expression\s*\(|@import|behavior\s*:|-moz-binding)/i.test(value)) {
                    element.removeAttribute(attribute.name);
                    continue;
                }
                if (!URL_ATTRIBUTES.has(name)) continue;
                if (name === 'href' && /^\s*javascript:/i.test(value)) {
                    const action = tag === 'a' ? parseScoutAction(value) : null;
                    element.removeAttribute(attribute.name);
                    if (action) setAction(element, action);
                    continue;
                }
                if (name === 'href' && allowedHref(value)) continue;
                if (name === 'src' && allowedAsset(value)) continue;
                element.removeAttribute(attribute.name);
            }
            if (tag === 'a' && element.getAttribute('target') === '_blank') {
                element.setAttribute('rel', 'noopener noreferrer');
            }
        }
        return template.innerHTML;
    }

    scope.parseScoutAction = parseScoutAction;
    scope.sanitizeReportHTML = sanitizeReportHTML;
    scope.scoutSafeHref = allowedHref;

    if (typeof document !== 'undefined') {
        document.addEventListener('click', function (event) {
            const link = event.target && event.target.closest &&
                event.target.closest('[data-scout-action]');
            if (!link) {
                const copy = event.target && event.target.closest &&
                    event.target.closest('[data-scout-copy-code]');
                if (copy) {
                    event.preventDefault();
                    const id = copy.getAttribute('data-scout-copy-code');
                    if (typeof id === 'string' && id.length <= 2048 &&
                            typeof scope.copyCode === 'function') scope.copyCode(id);
                }
                return;
            }
            event.preventDefault();
            event.stopPropagation();
            const name = link.getAttribute('data-scout-action');
            if (!ALLOWED_ACTIONS.has(name)) return;
            let args;
            try { args = JSON.parse(link.getAttribute('data-scout-args')); }
            catch (error) { return; }
            if (!Array.isArray(args) || args.length > 5 ||
                    args.some(x => typeof x !== 'string' || x.length > 2048)) return;
            const handler = scope[name];
            if (typeof handler === 'function') handler.apply(null, args);
        }, true);
    }
})(typeof window === 'undefined' ? globalThis : window);
