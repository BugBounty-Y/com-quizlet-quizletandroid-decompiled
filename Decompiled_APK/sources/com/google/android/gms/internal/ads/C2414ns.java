package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.ns, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2414ns {
    public final String a;
    public final boolean b;
    public final boolean c;
    public final long d;
    public final long e;

    public C2414ns(String str, boolean z, boolean z2, long j, long j2) {
        this.a = str;
        this.b = z;
        this.c = z2;
        this.d = j;
        this.e = j2;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C2414ns)) {
            return false;
        }
        C2414ns c2414ns = (C2414ns) obj;
        return this.a.equals(c2414ns.a) && this.b == c2414ns.b && this.c == c2414ns.c && this.d == c2414ns.d && this.e == c2414ns.e;
    }

    public final int hashCode() {
        return ((((((((((((this.a.hashCode() ^ 1000003) * 1000003) ^ (true != this.b ? 1237 : 1231)) * 1000003) ^ (true != this.c ? 1237 : 1231)) * 1000003) ^ 1237) * 1000003) ^ ((int) this.d)) * 1000003) ^ 1237) * 1000003) ^ ((int) this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AdShield2Options{clientVersion=");
        sb.append(this.a);
        sb.append(", shouldGetAdvertisingId=");
        sb.append(this.b);
        sb.append(", isGooglePlayServicesAvailable=");
        sb.append(this.c);
        sb.append(", enableQuerySignalsTimeout=false, querySignalsTimeoutMs=");
        sb.append(this.d);
        sb.append(", enableQuerySignalsCache=false, querySignalsCacheTtlSeconds=");
        return android.support.v4.media.session.a.g(this.e, "}", sb);
    }
}
