package com.braze.events.internal;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f {
    public final com.braze.requests.n a;

    public f(com.braze.requests.n request) {
        Intrinsics.checkNotNullParameter(request, "request");
        this.a = request;
        request.b();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && Intrinsics.b(this.a, ((f) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "DispatchFailedEvent(request=" + this.a + ')';
    }
}
