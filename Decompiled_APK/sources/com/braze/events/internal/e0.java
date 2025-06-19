package com.braze.events.internal;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e0 {
    public final String a;
    public final com.braze.models.outgoing.event.push.b b;

    public e0(String campaignId, com.braze.models.outgoing.event.push.b pushClickEvent) {
        Intrinsics.checkNotNullParameter(campaignId, "campaignId");
        Intrinsics.checkNotNullParameter(pushClickEvent, "pushClickEvent");
        this.a = campaignId;
        this.b = pushClickEvent;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e0)) {
            return false;
        }
        e0 e0Var = (e0) obj;
        return Intrinsics.b(this.a, e0Var.a) && Intrinsics.b(this.b, e0Var.b);
    }

    public final int hashCode() {
        return this.b.d.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "TriggerEligiblePushClickEvent(campaignId=" + this.a + ", pushClickEvent=" + this.b + ')';
    }
}
