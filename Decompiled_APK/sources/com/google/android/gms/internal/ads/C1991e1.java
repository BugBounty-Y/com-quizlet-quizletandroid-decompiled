package com.google.android.gms.internal.ads;

import java.util.Locale;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.e1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1991e1 {
    public final long a;
    public final long b;
    public final int c;

    public C1991e1(long j, long j2, int i) {
        AbstractC1795We.B(j < j2);
        this.a = j;
        this.b = j2;
        this.c = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C1991e1.class == obj.getClass()) {
            C1991e1 c1991e1 = (C1991e1) obj;
            if (this.a == c1991e1.a && this.b == c1991e1.b && this.c == c1991e1.c) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Objects.hash(Long.valueOf(this.a), Long.valueOf(this.b), Integer.valueOf(this.c));
    }

    public final String toString() {
        String str = Yo.a;
        Locale locale = Locale.US;
        return "Segment: startTimeMs=" + this.a + ", endTimeMs=" + this.b + ", speedDivisor=" + this.c;
    }
}
