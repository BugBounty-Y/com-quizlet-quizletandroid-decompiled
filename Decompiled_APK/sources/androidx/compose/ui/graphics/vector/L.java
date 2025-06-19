package androidx.compose.ui.graphics.vector;

import androidx.compose.animation.d0;
import androidx.compose.ui.graphics.AbstractC0857q;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class L extends J {
    public final String a;
    public final Object b;
    public final int c;
    public final AbstractC0857q d;
    public final float e;
    public final AbstractC0857q f;
    public final float g;
    public final float h;
    public final int i;
    public final int j;
    public final float k;
    public final float l;
    public final float m;
    public final float n;

    public L(String str, List list, int i, AbstractC0857q abstractC0857q, float f, AbstractC0857q abstractC0857q2, float f2, float f3, int i2, int i3, float f4, float f5, float f6, float f7) {
        this.a = str;
        this.b = list;
        this.c = i;
        this.d = abstractC0857q;
        this.e = f;
        this.f = abstractC0857q2;
        this.g = f2;
        this.h = f3;
        this.i = i2;
        this.j = i3;
        this.k = f4;
        this.l = f5;
        this.m = f6;
        this.n = f7;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || L.class != obj.getClass()) {
            return false;
        }
        L l = (L) obj;
        return this.a.equals(l.a) && Intrinsics.b(this.d, l.d) && this.e == l.e && Intrinsics.b(this.f, l.f) && this.g == l.g && this.h == l.h && this.i == l.i && this.j == l.j && this.k == l.k && this.l == l.l && this.m == l.m && this.n == l.n && this.c == l.c && Intrinsics.b(this.b, l.b);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        AbstractC0857q abstractC0857q = this.d;
        int iB = android.support.v4.media.session.a.b((iHashCode + (abstractC0857q != null ? abstractC0857q.hashCode() : 0)) * 31, this.e, 31);
        AbstractC0857q abstractC0857q2 = this.f;
        return Integer.hashCode(this.c) + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(d0.b(this.j, d0.b(this.i, android.support.v4.media.session.a.b(android.support.v4.media.session.a.b((iB + (abstractC0857q2 != null ? abstractC0857q2.hashCode() : 0)) * 31, this.g, 31), this.h, 31), 31), 31), this.k, 31), this.l, 31), this.m, 31), this.n, 31);
    }
}
