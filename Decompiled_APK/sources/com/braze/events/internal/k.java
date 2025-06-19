package com.braze.events.internal;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k {
    public final com.braze.requests.i a;

    public k(com.braze.requests.i request) {
        Intrinsics.checkNotNullParameter(request, "request");
        this.a = request;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof k) && Intrinsics.b(this.a, ((k) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "FeatureFlagsRequestSuccessEvent(request=" + this.a + ')';
    }
}
