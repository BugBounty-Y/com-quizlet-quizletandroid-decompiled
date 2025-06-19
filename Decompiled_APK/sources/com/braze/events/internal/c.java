package com.braze.events.internal;

import com.braze.requests.C1512a;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public final C1512a a;

    public c(C1512a request) {
        Intrinsics.checkNotNullParameter(request, "request");
        this.a = request;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && Intrinsics.b(this.a, ((c) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "BannersRequestSuccessEvent(request=" + this.a + ')';
    }
}
