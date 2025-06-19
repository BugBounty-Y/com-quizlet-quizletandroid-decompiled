package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.qq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2541qq implements InterfaceC2856y4 {
    public final long a;
    public final long b;
    public final long c;

    public C2541qq(long j, long j2, long j3) {
        this.a = j;
        this.b = j2;
        this.c = j3;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2856y4
    public final /* synthetic */ void a(L3 l3) {
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C2541qq)) {
            return false;
        }
        C2541qq c2541qq = (C2541qq) obj;
        return this.a == c2541qq.a && this.b == c2541qq.b && this.c == c2541qq.c;
    }

    public final int hashCode() {
        long j = this.a;
        int i = ((int) (j ^ (j >>> 32))) + 527;
        long j2 = this.b;
        return (((i * 31) + ((int) ((j2 >>> 32) ^ j2))) * 31) + ((int) this.c);
    }

    public final String toString() {
        return "Mp4Timestamp: creation time=" + this.a + ", modification time=" + this.b + ", timescale=" + this.c;
    }
}
