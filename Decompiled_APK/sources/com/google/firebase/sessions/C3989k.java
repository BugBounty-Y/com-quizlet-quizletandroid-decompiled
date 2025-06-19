package com.google.firebase.sessions;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.firebase.sessions.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3989k {
    public final EnumC3988j a;
    public final EnumC3988j b;
    public final double c;

    public C3989k(EnumC3988j performance, EnumC3988j crashlytics, double d) {
        Intrinsics.checkNotNullParameter(performance, "performance");
        Intrinsics.checkNotNullParameter(crashlytics, "crashlytics");
        this.a = performance;
        this.b = crashlytics;
        this.c = d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C3989k)) {
            return false;
        }
        C3989k c3989k = (C3989k) obj;
        return this.a == c3989k.a && this.b == c3989k.b && Double.compare(this.c, c3989k.c) == 0;
    }

    public final int hashCode() {
        return Double.hashCode(this.c) + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "DataCollectionStatus(performance=" + this.a + ", crashlytics=" + this.b + ", sessionSamplingRate=" + this.c + ')';
    }
}
