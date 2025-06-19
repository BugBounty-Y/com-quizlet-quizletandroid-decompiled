package com.google.android.gms.internal.ads;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.t3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2640t3 {
    public final String a;
    public final V1 b;
    public final D1 c;
    public final C2082g4 d;
    public final I0 e;

    static {
        C2244ju c2244ju = AbstractC2330lu.b;
        Bu bu = Bu.e;
        List list = Collections.EMPTY_LIST;
        E2 e2 = E2.a;
        new I0();
        C2082g4 c2082g4 = C2082g4.B;
        String str = Yo.a;
        Integer.toString(0, 36);
        Integer.toString(1, 36);
        Integer.toString(2, 36);
        Integer.toString(3, 36);
        Integer.toString(4, 36);
        Integer.toString(5, 36);
    }

    public /* synthetic */ C2640t3(String str, I0 i0, V1 v1, D1 d1, C2082g4 c2082g4) {
        E2 e2 = E2.a;
        this.a = str;
        this.b = v1;
        this.c = d1;
        this.d = c2082g4;
        this.e = i0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C2640t3)) {
            return false;
        }
        C2640t3 c2640t3 = (C2640t3) obj;
        if (!this.a.equals(c2640t3.a) || !this.e.equals(c2640t3.e) || !Objects.equals(this.b, c2640t3.b) || !this.c.equals(c2640t3.c) || !Objects.equals(this.d, c2640t3.d)) {
            return false;
        }
        E2 e2 = E2.a;
        return e2.equals(e2);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        V1 v1 = this.b;
        return (this.d.hashCode() + ((this.e.hashCode() + ((this.c.hashCode() + ((iHashCode + (v1 != null ? v1.hashCode() : 0)) * 31)) * 31)) * 31)) * 31;
    }
}
