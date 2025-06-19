package com.braze.events.internal;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g0 {
    public final com.braze.triggers.events.b a;
    public final com.braze.triggers.actions.a b;

    public g0(com.braze.triggers.events.b originalTriggerEvent, com.braze.triggers.actions.a failedTriggeredAction) {
        Intrinsics.checkNotNullParameter(originalTriggerEvent, "originalTriggerEvent");
        Intrinsics.checkNotNullParameter(failedTriggeredAction, "failedTriggeredAction");
        this.a = originalTriggerEvent;
        this.b = failedTriggeredAction;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g0)) {
            return false;
        }
        g0 g0Var = (g0) obj;
        return Intrinsics.b(this.a, g0Var.a) && Intrinsics.b(this.b, g0Var.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "TriggeredActionRetryEvent(originalTriggerEvent=" + this.a + ", failedTriggeredAction=" + this.b + ')';
    }
}
