package com.braze.events.internal;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class r {
    public final com.braze.requests.b a;

    public r(com.braze.requests.b request) {
        Intrinsics.checkNotNullParameter(request, "request");
        this.a = request;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof r) && Intrinsics.b(this.a, ((r) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "RequestDispatchStartedEvent(request=" + this.a + ')';
    }
}
