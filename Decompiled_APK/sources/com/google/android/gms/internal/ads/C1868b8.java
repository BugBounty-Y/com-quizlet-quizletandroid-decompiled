package com.google.android.gms.internal.ads;

import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.b8, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1868b8 {
    public final Object a;
    public final int b;
    public final C2640t3 c;
    public final Object d;
    public final int e;
    public final long f;
    public final long g;
    public final int h;
    public final int i;

    static {
        String str = Yo.a;
        Integer.toString(0, 36);
        Integer.toString(1, 36);
        Integer.toString(2, 36);
        Integer.toString(3, 36);
        Integer.toString(4, 36);
        Integer.toString(5, 36);
        Integer.toString(6, 36);
    }

    public C1868b8(Object obj, int i, C2640t3 c2640t3, Object obj2, int i2, long j, long j2, int i3, int i4) {
        this.a = obj;
        this.b = i;
        this.c = c2640t3;
        this.d = obj2;
        this.e = i2;
        this.f = j;
        this.g = j2;
        this.h = i3;
        this.i = i4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && C1868b8.class == obj.getClass()) {
            C1868b8 c1868b8 = (C1868b8) obj;
            if (this.b == c1868b8.b && this.e == c1868b8.e && this.f == c1868b8.f && this.g == c1868b8.g && this.h == c1868b8.h && this.i == c1868b8.i && Objects.equals(this.c, c1868b8.c) && Objects.equals(this.a, c1868b8.a) && Objects.equals(this.d, c1868b8.d)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Objects.hash(this.a, Integer.valueOf(this.b), this.c, this.d, Integer.valueOf(this.e), Long.valueOf(this.f), Long.valueOf(this.g), Integer.valueOf(this.h), Integer.valueOf(this.i));
    }
}
