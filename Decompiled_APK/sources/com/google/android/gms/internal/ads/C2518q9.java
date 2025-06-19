package com.google.android.gms.internal.ads;

import android.net.Uri;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.tagmanager.ModuleDescriptor;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.q9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2518q9 {
    public static final Object m = new Object();
    public static final C2640t3 n;
    public Object a = m;
    public C2640t3 b = n;
    public long c;
    public long d;
    public long e;
    public boolean f;
    public boolean g;
    public D1 h;
    public boolean i;
    public long j;
    public int k;
    public int l;

    static {
        C2244ju c2244ju = AbstractC2330lu.b;
        Bu bu = Bu.e;
        List list = Collections.EMPTY_LIST;
        Bu bu2 = Bu.e;
        E2 e2 = E2.a;
        Uri uri = Uri.EMPTY;
        n = new C2640t3("androidx.media3.common.Timeline", new I0(), uri != null ? new V1(uri, bu2) : null, new D1(), C2082g4.B);
        String str = Yo.a;
        Integer.toString(1, 36);
        Integer.toString(2, 36);
        Integer.toString(3, 36);
        Integer.toString(4, 36);
        Integer.toString(5, 36);
        Integer.toString(6, 36);
        Integer.toString(7, 36);
        Integer.toString(8, 36);
        Integer.toString(9, 36);
        Integer.toString(10, 36);
        Integer.toString(11, 36);
        Integer.toString(12, 36);
        Integer.toString(13, 36);
    }

    public final void a(C2640t3 c2640t3, boolean z, boolean z2, D1 d1, long j) {
        this.a = m;
        if (c2640t3 == null) {
            c2640t3 = n;
        }
        this.b = c2640t3;
        this.c = -9223372036854775807L;
        this.d = -9223372036854775807L;
        this.e = -9223372036854775807L;
        this.f = z;
        this.g = z2;
        this.h = d1;
        this.j = j;
        this.k = 0;
        this.l = 0;
        this.i = false;
    }

    public final boolean b() {
        return this.h != null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !C2518q9.class.equals(obj.getClass())) {
            return false;
        }
        C2518q9 c2518q9 = (C2518q9) obj;
        return Objects.equals(this.a, c2518q9.a) && Objects.equals(this.b, c2518q9.b) && Objects.equals(this.h, c2518q9.h) && this.c == c2518q9.c && this.d == c2518q9.d && this.e == c2518q9.e && this.f == c2518q9.f && this.g == c2518q9.g && this.i == c2518q9.i && this.j == c2518q9.j && this.k == c2518q9.k && this.l == c2518q9.l;
    }

    public final int hashCode() {
        int iHashCode = ((this.a.hashCode() + ModuleDescriptor.MODULE_VERSION) * 31) + this.b.hashCode();
        D1 d1 = this.h;
        int iHashCode2 = ((iHashCode * 961) + (d1 == null ? 0 : d1.hashCode())) * 31;
        long j = this.c;
        int i = (iHashCode2 + ((int) (j ^ (j >>> 32)))) * 31;
        long j2 = this.d;
        int i2 = (i + ((int) (j2 ^ (j2 >>> 32)))) * 31;
        long j3 = this.e;
        int i3 = ((((((i2 + ((int) (j3 ^ (j3 >>> 32)))) * 31) + (this.f ? 1 : 0)) * 31) + (this.g ? 1 : 0)) * 31) + (this.i ? 1 : 0);
        long j4 = this.j;
        return ((((((i3 * 961) + ((int) (j4 ^ (j4 >>> 32)))) * 31) + this.k) * 31) + this.l) * 31;
    }
}
