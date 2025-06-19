package com.braze.events.internal;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class o {
    public final com.braze.enums.f a;
    public final com.braze.enums.f b;

    public o(com.braze.enums.f oldNetworkLevel, com.braze.enums.f newNetworkLevel) {
        Intrinsics.checkNotNullParameter(oldNetworkLevel, "oldNetworkLevel");
        Intrinsics.checkNotNullParameter(newNetworkLevel, "newNetworkLevel");
        this.a = oldNetworkLevel;
        this.b = newNetworkLevel;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return this.a == oVar.a && this.b == oVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "NetworkLevelChangeEvent(oldNetworkLevel=" + this.a + ", newNetworkLevel=" + this.b + ')';
    }
}
