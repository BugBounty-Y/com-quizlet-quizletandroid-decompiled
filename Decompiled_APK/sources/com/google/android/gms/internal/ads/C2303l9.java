package com.google.android.gms.internal.ads;

import com.google.android.gms.dynamite.descriptors.com.google.android.gms.tagmanager.ModuleDescriptor;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.l9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2303l9 {
    public Integer a;
    public Object b;
    public int c;
    public long d;
    public boolean e;
    public P5 f = P5.b;

    static {
        String str = Yo.a;
        Integer.toString(0, 36);
        Integer.toString(1, 36);
        Integer.toString(2, 36);
        Integer.toString(3, 36);
        Integer.toString(4, 36);
    }

    public final long a(int i, int i2) {
        C1815a c1815aA = this.f.a(i);
        if (c1815aA.a != -1) {
            return c1815aA.e[i2];
        }
        return -9223372036854775807L;
    }

    public final void b(Integer num, Object obj, int i, long j, boolean z) {
        P5 p5 = P5.b;
        this.a = num;
        this.b = obj;
        this.c = i;
        this.d = j;
        this.f = p5;
        this.e = z;
    }

    public final void c(int i) {
        this.f.a(i).getClass();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !C2303l9.class.equals(obj.getClass())) {
            return false;
        }
        C2303l9 c2303l9 = (C2303l9) obj;
        return Objects.equals(this.a, c2303l9.a) && Objects.equals(this.b, c2303l9.b) && this.c == c2303l9.c && this.d == c2303l9.d && this.e == c2303l9.e && Objects.equals(this.f, c2303l9.f);
    }

    public final int hashCode() {
        Integer num = this.a;
        int iHashCode = num == null ? 0 : num.hashCode();
        Object obj = this.b;
        int iHashCode2 = ((((iHashCode + ModuleDescriptor.MODULE_VERSION) * 31) + (obj != null ? obj.hashCode() : 0)) * 31) + this.c;
        long j = this.d;
        return this.f.hashCode() + (((((iHashCode2 * 31) + ((int) (j ^ (j >>> 32)))) * 961) + (this.e ? 1 : 0)) * 31);
    }
}
