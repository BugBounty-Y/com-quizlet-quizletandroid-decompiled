package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.d1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1948d1 implements InterfaceC2856y4 {
    public final long a;
    public final long b;
    public final long c;
    public final long d;
    public final long e;

    public C1948d1(long j, long j2, long j3, long j4, long j5) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
        this.e = j5;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2856y4
    public final /* synthetic */ void a(L3 l3) {
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C1948d1.class == obj.getClass()) {
            C1948d1 c1948d1 = (C1948d1) obj;
            if (this.a == c1948d1.a && this.b == c1948d1.b && this.c == c1948d1.c && this.d == c1948d1.d && this.e == c1948d1.e) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        long j = this.a;
        int i = ((int) (j ^ (j >>> 32))) + 527;
        long j2 = this.e;
        long j3 = j2 ^ (j2 >>> 32);
        long j4 = this.d;
        long j5 = j4 ^ (j4 >>> 32);
        long j6 = this.c;
        long j7 = j6 ^ (j6 >>> 32);
        long j8 = this.b;
        return (((((((i * 31) + ((int) ((j8 >>> 32) ^ j8))) * 31) + ((int) j7)) * 31) + ((int) j5)) * 31) + ((int) j3);
    }

    public final String toString() {
        return "Motion photo metadata: photoStartPosition=" + this.a + ", photoSize=" + this.b + ", photoPresentationTimestampUs=" + this.c + ", videoStartPosition=" + this.d + ", videoSize=" + this.e;
    }
}
