// Response playbooks: checklists an analyst applies to an investigation.
// Steps describe actions taken in the organisation's own tools (mail gateway,
// identity provider, EDR); this platform records them and never performs or
// fetches anything itself. Keep each step one action, under 200 characters.

export const PLAYBOOKS = Object.freeze([
  {
    id: "credential-phishing",
    name: "Credential phishing",
    steps: [
      "Identify every recipient of the message and who clicked the link or replied",
      "Block the sender address and the lure domains at the mail gateway and web proxy",
      "Remove the message from all mailboxes",
      "Reset passwords and revoke sessions for anyone who entered credentials",
      "Check sign-in logs of affected accounts for unusual locations or MFA changes",
      "Record the lure domains, hosts and URLs as indicators",
      "Tell the people who reported it what was found, and close the alerts with a disposition",
    ],
  },
  {
    id: "malware-delivery",
    name: "Malware attachment or download",
    steps: [
      "Identify recipients who opened the attachment or followed the download link",
      "Isolate affected endpoints and collect their EDR alerts",
      "Block the attachment hash, the sender and the download domains",
      "Remove the message from all mailboxes",
      "Scan or reimage affected endpoints and confirm they are clean",
      "Record the domains, hosts, IP addresses and URLs as indicators",
      "Tell the people who reported it what was found, and close the alerts with a disposition",
    ],
  },
  {
    id: "payment-fraud",
    name: "Business email compromise or payment fraud",
    steps: [
      "Confirm the request with the real requester through a known phone number, not the email",
      "Stop or recall any payment already made and contact the bank's fraud team",
      "Check whether a real mailbox was compromised: sign-ins, forwarding and inbox rules",
      "Block the look-alike sender domains",
      "Brief finance staff and executive assistants on the lure",
      "Record the indicators and note every contact made, with times",
    ],
  },
  {
    id: "brand-impersonation",
    name: "Brand impersonation site",
    steps: [
      "Capture evidence of the site from an isolated analysis environment (this platform never visits it)",
      "Record the domain, host and IP indicators",
      "Report the site to the registrar, the hosting provider and the impersonated brand",
      "Track takedown requests and their reference numbers in the notes",
      "Block the domains at the web proxy until the takedown is confirmed",
      "Confirm the takedown and close the investigation",
    ],
  },
]);

export const playbookById = (id) => PLAYBOOKS.find((p) => p.id === id) ?? null;
