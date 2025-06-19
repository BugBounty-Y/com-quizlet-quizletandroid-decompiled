package com.braze.events.internal;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h {
    public final String a;

    public h(String mite) {
        Intrinsics.checkNotNullParameter(mite, "mite");
        this.a = mite;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && Intrinsics.b(this.a, ((h) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return androidx.compose.animation.d0.r(new StringBuilder("DustMiteReceivedEvent(mite="), this.a, ')');
    }
}
