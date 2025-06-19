package com.braze.events.internal;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class z {
    public final com.braze.models.n a;

    public z(com.braze.models.n sealedSession) {
        Intrinsics.checkNotNullParameter(sealedSession, "sealedSession");
        this.a = sealedSession;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof z) && Intrinsics.b(this.a, ((z) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SessionSealedEvent(sealedSession=" + this.a + ')';
    }
}
