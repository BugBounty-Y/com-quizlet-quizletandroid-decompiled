package com.braze.events.internal;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d {
    public final com.braze.models.response.m a;
    public final com.braze.models.response.m b;

    public d(com.braze.models.response.m oldConfig, com.braze.models.response.m newConfig) {
        Intrinsics.checkNotNullParameter(oldConfig, "oldConfig");
        Intrinsics.checkNotNullParameter(newConfig, "newConfig");
        this.a = oldConfig;
        this.b = newConfig;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Intrinsics.b(this.a, dVar.a) && Intrinsics.b(this.b, dVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ConfigChangeEvent(oldConfig=" + this.a + ", newConfig=" + this.b + ')';
    }
}
