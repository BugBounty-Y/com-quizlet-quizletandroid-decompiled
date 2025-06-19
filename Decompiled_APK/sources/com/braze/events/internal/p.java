package com.braze.events.internal;

/* loaded from: classes.dex */
public final class p {
    public final long a;

    public p(long j) {
        this.a = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof p) && this.a == ((p) obj).a;
    }

    public final int hashCode() {
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return androidx.compose.animation.d0.q(new StringBuilder("PushMaxRequestSuccessEvent(lastUpdateTime="), this.a, ')');
    }
}
