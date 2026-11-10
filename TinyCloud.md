MEMO: TinyCloud – Building Interoperable, Sovereign Apps and Data

1. Overview and Motivation

TinyCloud is a framework for interoperable applications built around user-controlled data spaces and capability-based access. As the cost of writing software approaches zero—largely due to advances in AI and the commoditization of development—the true competitive moats are shifting to data and network effects. TinyCloud lets individuals and organizations grant apps and agents scoped access to shared data without tying that data to one application. This product vision includes proposed capabilities, not guarantees of current deployment behavior.

By consolidating data—ranging from real-time location to personal conversation transcripts—users can unlock transformative, AI-driven capabilities that would otherwise be locked in proprietary silos. TinyCloud is grounded in the conviction that sovereignty, privacy, and the user’s agency must remain central as AI applications become increasingly powerful.

2. Core Values
	1.	Sovereignty
	•	TinyCloud uses capabilities to let users approve scoped access to their data. Hosted operators and authorized processing services remain within the trust boundary.
	•	This design is intended to resist the looming dynamics of “techno-feudalism,” in which corporations or states control the rails and data exhaust of all AI applications.
	2.	Privacy
	•	Capability-based access lets users choose the scopes granted to apps and agents.
	•	Ordinary data on hosted nodes is currently stored in plaintext at rest. TinyCloud does not currently provide encryption at rest or end-to-end encryption for that stored data; operators can access unencrypted values.
	•	A limited answer, such as whether you are in a city, can reduce what a recipient receives; it does not hide the underlying location from the service processing it.
	3.	Interoperability
	•	Embracing artifact-based formats—Markdown, JSON Canvas, CSV, and SQLite—so that data remains portable and future-proof.
	•	If any one TinyCloud-based app fails, your data remains accessible in standard file formats or in other interoperable apps.
	4.	With Open Arms We Welcome that which would Destroy Us
	•	TinyCloud views AI’s rapid growth not as something to resist passively, but an opportunity to endow individuals with new capabilities—before these capabilities are seized exclusively by large institutions.

3. What We Are Building

a) TinyCloud Framework
	1.	Goal
	•	Provide a decentralized or user-controlled “cloud” that can serve as the back end for multiple apps.
	•	Instead of data silos, each user has a single, cohesive store of data (e.g., location, transcripts, knowledge graphs) that authorized apps can read or process.
	2.	Key Components
	•	Key-Value Store & Buckets: Simple, flexible storage (akin to an S3-like interface).
	•	Compute Layer: Functions or queries can return limited answers, such as “Am I within 1 km of my friend?” The service processing the query may still read the underlying data.
	•	Capabilities: Scoped permissions define which resources and actions an app or agent may use. They do not encrypt those resources.
	3.	First Use Cases
	•	Location Streamer: An app that continuously streams a user’s location into their TinyCloud node.
	•	‘Find My Friends’ Clone: A proposed app that shares a nearby-or-in-city result with a friend rather than an entire location history. Hosted processing still has access to the underlying data.
	4.	Free & Paid Tiers
	•	The overarching plan is to offer a free tier (basic storage, limited compute) and a paid tier (expanded storage, advanced compute, premium encryption or replication features).

b) Autograph

Autograph is the structured knowledge layer and API designed to store and retrieve user data—especially unstructured text like transcripts—while converting it into an interlinked knowledge graph.
	1.	Primary Functions
	•	(text, bucket) ⇒ updates the bucket with structured notes/graph nodes
	•	(query, bucket) ⇒ retrieves relevant knowledge graph nodes
	•	This means a user (or an AI agent working on their behalf) can pass large text blocks—say a conversation transcript—and Autograph will parse it into nodes (people, places, organizations, concepts) and link them.
	2.	Integration with LLMs & Tools
	•	Can be plugged into a “Model Context Protocol,” enabling AI agents to store new facts or retrieve relevant context as they chat with you.
	•	Sync Options:
	•	GitHub Sync so that Obsidian (and other markdown-based knowledge-management tools) stays updated.
	•	TinyCloud Sync for sovereign data hosting.
	•	Potential Obsidian direct sync: bridging local markdown-based vaults and the cloud.
	3.	User & AI Agent Use
	•	Humans can search or retrieve notes easily; AI agents can be permissioned to read or write data, constructing deeper contexts for better language model reasoning.
	4.	Free & Paid Tiers
	•	Basic usage (smaller transcripts, short queries) may be free. Larger, heavier usage would require a paid tier.

c) Muse

Muse is a capture tool and personal AI companion app that integrates seamlessly with TinyCloud and Autograph.
	1.	Core Idea: A “Software Pendant”
	•	Users wear a lightweight audio capture device—“the pendant”—that records real-life conversations (with consent).
	•	Muse continuously or selectively transcribes these conversations and funnels them into Autograph for structuring.
	2.	Use Cases
	•	In-Person AI Scribe: Real-time or offline transcription of meetings, classes, personal notes.
	•	Lifetime Memory: Over time, you build a personal knowledge base of everything you’ve said or learned, which you own.
	•	Lenses: Summaries or “views” through your data—for instance, automatically pulling up relevant notes from past conversations.
	•	Infinite Scroller of insights: Instead of an algorithm designed for ads, you have a feed of contextually important or personally enriching information from your own knowledge base.
	3.	Target Demographics & Launch
	•	Early adopters—knowledge workers, creators, or “quantified-self” enthusiasts.
	•	Potential influencer marketing: Show how wearing a personal AI scribe solves note-taking, research, or creative-block issues.
	4.	Free & Paid Tiers
	•	Basic app features for short transcripts or limited usage.
	•	Premium for larger, continuous audio logs, advanced integrations, AI summarizations, etc.

4. Access Control and Encryption Boundaries
	•	Users grant apps and agents capability scopes for the data they need.
	•	Signing with your own wallet keeps its key under your control. OpenKey-managed keys use a separate service custody model; signing keys do not by themselves encrypt stored data.
	•	Revocation support and limits depend on the access path. Ending access cannot recall copies already read.
	•	Encryption at rest is planned, not a current hosted-storage guarantee. See the [at-rest implementation status](docs/at-rest/INTERFACES.md).
	•	See [Security and trust](https://docs.tinycloud.xyz/concepts/security-and-trust) for operator access, application-specific encryption, key custody and authorized-client boundaries.

5. Potential Apps and Extensions
	1.	Chat App Clone
	•	Sovereign text or “canvas” chat, with the ability to pull relevant knowledge graph references directly into conversation.
	2.	Personal Analytics
	•	From heart rate correlating with location or conversation transcripts, to advanced “personal RAG” (Retrieval-Augmented Generation) scenarios.
	3.	Creative Tools
	•	AI-powered storyboarding, brainstorming, or rewriting using the knowledge base you authorize it to read. The processing service receives the context it uses.

6. Risks
	1.	Competitive Landscape
	•	Others may build a similar “personal cloud” or “solid POD” approach. Tim Berners-Lee’s SOLID project and other Linked Data ecosystems share similar goals. Risk of fragmentation or incompatible standards.
	2.	Niche Outcome
	•	The end result could be a small, privacy-focused community, akin to how cryptocurrency co-exists with mainstream finance. While it may remain niche, it can still provide valuable user sovereignty.
	3.	Regulatory/Legal Concerns
	•	Wearable AI devices (pendants) may face legal restrictions, especially around surreptitious recording. Certain privacy-preserving technologies might be banned or limited in different jurisdictions.
	•	Sovereign data ownership poses compliance questions around lawful requests (e.g., government subpoenas).

7. Conclusion

TinyCloud is a bold move toward individual empowerment in an era where AI can otherwise centralize knowledge and control in the hands of the few. By combining:
	•	A user-owned TinyCloud back end (storage + compute),
	•	A flexible knowledge-layer in Autograph, and
	•	A frictionless capture/UI approach with Muse,

we aim to reimagine how people store, access, and truly own their personal data—while still harnessing the best of AI. The TinyCloud ecosystem aspires to show that the future of intelligence need not culminate in “techno-feudalism,” but can, instead, distribute its benefits widely and with respect for human agency and privacy.

Next Steps / Action Items
	1.	Finalize TinyCloud MVP: Key-Value Store + basic compute demonstration with location streaming.
	2.	Release Autograph API: Accept transcripts, build the knowledge graph, sync via Git or TinyCloud.
	3.	Refine Muse: Expand real-time transcription, improve AI summarization, and offer a more intuitive UI for capturing and browsing transcripts.
	4.	Plan for Designer Hiring: Once traction is shown, bring on world-class UX/UI designers to craft user-friendly, sovereignty-first experiences.
	5.	Expand Encryption & Permissioning: Continue the planned at-rest work and evaluate additional encryption approaches without presenting them as shipped guarantees.

These proposals aim to support interoperable personal AI with user-controlled access. Current security boundaries and implementation limits remain those described in [Security and trust](https://docs.tinycloud.xyz/concepts/security-and-trust).