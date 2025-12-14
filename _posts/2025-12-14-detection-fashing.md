---
layout: post
title: "Detection isn't a fashion statement"
date: 25-12-14 12:05:00 +0200  
categories: [OT, DE]
tags: [safety, DE]
description: "How Hazard Analysis maps onto Detection Engineering workflows"
comments: false
---

# Introductory Ramblings
---

It is common in this field for people to wrap a lot of their identity and pride into the technology or tools they use. It is not entirely unreasonable since it is natural to feel strongly about something you have spent years mastering while feeling a bit hostile toward anything that might push aside what you built or want to build.

But these barriers should never distort how you look at problems. It should never be about forcing everything through your preferred tool but rather choosing the tool that fits the job. That point has been made countless times so I will not linger on it, but it is still something I see constantly in detection engineering online. The idea of compensating measures or the classic security artichoke is rarely represented with the same maturity you find when talking with security architects. Even there you meet people who question why you need anything beyond an EDR or now an XDR. 

Detection engineering has been on a hype streak lately with courses, blog posts, videos and inspirational nonsense on LinkedIn. Most of it is the usual garbage aimed at people attracted to the idea of building detection coverage and willing to pay for someone’s packaged concept of what the work is. They show off tools and tech and shiny demonstrations that make you think you are getting your money’s worth, but they rarely represent what you will actually deal with or, more importantly, how you should approach detection engineering whatever that term even means.

I always tell people to read the documentation instead of hoping a video will fix things. The docs and the grind are what make you understand the technology, but reflecting on your own work is what helps you break out of silo thinking and approach problems from angles no one taught you. Think critically about what you do and take a few steps back before diving into a problem.

What I hope to achieve with this post is to start a conversation regarding tackling the creation of detection content.
# Why are we here...
---

That is exactly what we are doing today. Taking a few steps back and reflecting on detection as a concept for solving a problem finding behaviour and artifacts in our environments that we consider interesting and worth noting. That is all. We are not discussing whether the things we observe are malicious.

So let us start simple. Let us try to formulate a problem statement.

I read an article the other day about using proxies inside enterprise networks to act as anchors or internal servers through which commands can be routed to other endpoints. It is basically a jump host setup but from the perspective of a threat actor or someone doing unexpected admin work/s. I want to explore how to find this kind of behaviour and these types of artifacts in my environment.

We know something at a high level: traffic hits an endpoint, and traffic comes out. We are dealing with a common TLS-based protocol. Fine.

Now let us be a bit Socratic.

Is it normal for traffic to go directly to an endpoint?  
Does it matter whether that endpoint is a workstation or a server?  
Does it vary by office location or by time of day?  
Does the type of server matter, its role, or where it sits in the network?

If this _is_ normal or _not_ normal, what protocols do we then expect to see?  
What kinds of data flows appear?  
What do the TLS handshakes actually look like in these situations?

When traffic enters and exits an endpoint, does it utilize randomized local ports to direct that traffic?

There’s no real question that is stupid in this situation. Asking whether it’s normal for data to traverse a client might, at face value, sound naïve, but what we are really looking for is an entry point. Somewhere we can start to tackle the issue.

What we want is to connect answers to for example:

- data sources
- fields
- observable behaviours
- interference patterns
- similar techniques
- methods to approach the problem (atomic, heuristic, RBA, models, ML, graphs etc)

My way of structuring this type of research is to reach into my OT bag and pull out hazard analysis and its associated frameworks, primarily looking through the lenses of:

- conceptual analysis
- preliminary analysis
- detailed analysis
- system analysis
- operations analysis
- requirements analysis

This will help us structure the work much better, you don't need to make so official, but I tend to at least mentally try to separate my work in logical steps so I don't rush writing something not fulfilling my requirements for the detection. 
# Wait, was this all bait for OT...? ( Yes )
---
I won’t spend too much time on these steps, but I thought it would be interesting to explore how these types of frameworks can be leveraged in other fields.
## Conceptual Analysis

The conceptual phase is about the initial reaction to the problem. We were just told to create a detection ( or detections ) for this and are now coming up with initial places to start looking. We do not need to go into details here, just a high-level list of things we want to examine going in, perhaps including previous work that could be referenced to get a foothold.

## Preliminary Analysis

We are still not worried about details, but we are starting to look at the issue at a high-level system ( event ) perspective. What requirements might exist for satisfying the detection? What relationships are we seeing between endpoints, internal servers, and outgoing traffic?

## Detailed Analysis

Once we start learning more about our data and the potential attack technique, we can go deeper. We want to define interfaces, traffic flows, fields, bytes, sessions, and so on to get a solid idea of what we are actually looking at. This phase can add lower-level requirements: are there opportunities to constrain interfaces, ports, protocols, or other components where we can define scope?

## System Analysis

With a clearer understanding of the components and the technique at a lower level, we take a more holistic look at the system. How do the components we just examined integrate with each other, and how does that combined behaviour present itself in our environment; can we see a red thread to our detection story? 

## Operations Analysis

Operational analysis is usually meant to surface potential hazards with respect to operations and support functions of a system. Here, I instead look at it from the perspective of the environment: how do operations actually look, and how will an analyst interact with the detection? This helps focus additional attention on usability, investigative flow, and operational friction.

## Requirements Analysis

Requirements analysis is a strong driver for finishing parts of detection development. It forces you to continuously verify what you are building against the requirements you are defining throughout the engagement. It is essentially a mechanism that drives the detection to completion rather than letting it stall as an interesting, but incomplete, idea.

# Validating against the requirements ( V&V...? )

As most of us know, validation is the most important part of any development effort. We must ensure that what we build aligns with the requirements we defined and that it functions as intended. While ongoing requirement verification focuses on whether we are building things correctly, this step confirms that we built the right thing. This is still a relatively new area, with limited enterprise tooling available to support automation. Regardless of automation maturity, access to an environment that allows us to simulate intended attacks remains essential. This enables log generation, validation of detection triggers, and packaging of detection content alongside the associated validation data.

# Reframing the problem statement 

Having survived that OT detour we can go back to redefine our initial problem statement through this new lens of ours. 

We want to identify endpoint-mediated traffic relay behaviour ( that's a mouthful ) inside an enterprise network, where a workstation or server receives inbound connection and subsequently initiates outbound connections that appear functionality related, effectively acting as an internal proxy. This, as we know, can't be judged as malicious by default; the goal is to surface behavioural patterns and artifact that are sufficiently unusual, policy-breaking, or operationally interesting to warrant analyst review and possible engagement. 

The challenge we're facing isn't inspection of the packets in isolation, neither attribution of intent, but rather understanding how traffic transits endpoints, how that behaviours varies by role and context, and how those relationships manifest across our available telemetry. 

This approach avoids tool-centric assumptions and instead treats detection as a systems-observation problem. 

## From theory to practice

Let us take what we have discussed and put it into practice by mapping this framework onto detection engineering workflows. I will try to keep each section as short as possible, focusing on the main point.

### **HA-CA** - Environment Normalcy Modelling

At this stage, we need to identify the current potential hazard, which is incorrect assumptions about normal system behaviour. If we get this wrong, it will have a ripple effect throughout the remaining stages.

Our questions then become:

- Endpoint classes receiving unsolicited inbound traffic → defining allowed exposure surfaces
- Immediate outbound TLS following inbound traffic → identifying relay-capable system states
- Role, zone, and time-of-day variance → bounding operational envelopes

What we are then producing here is:

- operational assumptions
- environmental constraints
- initial exclusions

If your spider senses are tingling, it might be because we are metalizing baselines and profiles.

### **HA-PA** - Data Source and Telemetry Mapping

Moving on from initial system-wide behaviour, we look more closely at our observability. We want to be able to detect when our system moves into an unsafe or otherwise interesting state.

These then become our telemetry questions:

- NetFlow, EDR, TLS metadata, firewall logs, Zeek, Suricata → identifying observable interfaces
- Bidirectional correlation on a single host → defining minimum sensing requirements

Where the implicit detection requirements then become:

- Can ingress and egress be correlated at all?
- Is host identity preserved across data sources?
- Are timestamps precise enough to support causal reasoning?

By looking at the interfaces, we are creating a matrix of where we can find our telemetry, while also producing a gap analysis in cases where we are not logging the required data.
### **HA-DA** - Observable Behavioural Patterns

Having completed the groundwork and prepared with both a holistic view of the system and a more detailed understanding of our observability, we are now looking at the mischaracterization of interacting systems. We want to avoid confusing coincidence with causality, or missing subtle interactions between components.

- inbound → outbound time deltas → temporal coupling
- PID or user reuse → control continuity
- fan-in / fan-out ratios → structural amplification
- ephemeral port behaviour → protocol role violations

If you know your detection engineering ABCs, you might start recognizing the type of detection we are now staring down. I wouldn’t call these alerts, but rather hazard indicators. If this were a formal hazard analysis, an FMEA would likely be in order, and it may fit here as well.

### **HA-SA** - Detection Strategy Options

This is where many people start, unfortunately—trying to fit a detection idea into a pre-planned method rather than doing the necessary due diligence. The hazard is that we end up building something that is locally optimized while failing to understand system-level behaviour.

To bring this back into systems analysis:

- How do individual components interact?
- What emergent behaviours arise from their combination?

Once we understand that, the following becomes easier to relate to:

- Atomic detections → component-level hazard checks
- Heuristic scoring (models) → multi-signal interaction modelling
- Risk-based alerts (RBA) → cumulative exposure analysis
- Graph (ML) approaches → structural system modelling

Each method comes with its own pros and cons and provides a different way to model system coupling and propagation.

### **HA-OA** - Operationalization and Analyst Experience

Let’s move on from the detection content and focus on the analyst, who, in operation, will have to respond to the trigger. If we can’t provide a good interface for the analyst, it doesn’t matter if our detection is correct; it won’t be acted on safely, consistently, or in time.

The questions we need to address are:

- human-system interaction
- response workflows
- friction and failure points

From these, it naturally follows:

- Clear “why” → hazard explanation
- Supporting context → situational awareness
- Obvious next steps → safe operational response

By understanding your analysts’ workloads and knowledge, these then become secondary hazards that need to be addressed:

- analyst overload
- misinterpretation
- inconsistent handling

Failing on these is just as serious as failing in the detection logic itself.
### **HA-RA+V&V** - Validation and Continuous Verification

As I mentioned earlier, this is perhaps one of the most important stages, often overlooked due to the technical complexity it may bring. Validation of the requirements serves as a certificate of approval, showing that you have gone through each stage meticulously and have now provided detection content that reflects the requirements. It helps us provide accurate data to stakeholders and gives real confidence that things are working as intended and are measurable.

These are the three pillars with need to tackle: 

- requirements → testable conditions
- simulations → controlled hazard induction
- regression testing → change impact analysis

Without these, our library of detection content becomes merely a collection of hypotheses rather than effective controls.

# Before I go... 

To really hit on what we've done here is to anchor the problem in systems behaviour rather than adversary identity, and by structuring analysing through explicit phases, detection engineering becomes less about the tool and more about disciplined observation. 

Br,


