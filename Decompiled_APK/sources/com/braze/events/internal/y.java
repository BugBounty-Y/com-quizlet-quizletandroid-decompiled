package com.braze.events.internal;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class y {
    public final com.braze.models.l a;

    public y(com.braze.models.l session) {
        Intrinsics.checkNotNullParameter(session, "session");
        this.a = session;
        if (session.d) {
            throw new IllegalArgumentException("Session created events cannot be created with already sealed sessions.");
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof y) && Intrinsics.b(this.a, ((y) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SessionCreatedEvent(session=" + this.a + ')';
    }
}
