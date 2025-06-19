package androidx.compose.material3;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class Y4 {
    public final androidx.compose.ui.text.L a;
    public final androidx.compose.ui.text.L b;
    public final androidx.compose.ui.text.L c;
    public final androidx.compose.ui.text.L d;
    public final androidx.compose.ui.text.L e;
    public final androidx.compose.ui.text.L f;
    public final androidx.compose.ui.text.L g;
    public final androidx.compose.ui.text.L h;
    public final androidx.compose.ui.text.L i;
    public final androidx.compose.ui.text.L j;
    public final androidx.compose.ui.text.L k;
    public final androidx.compose.ui.text.L l;
    public final androidx.compose.ui.text.L m;
    public final androidx.compose.ui.text.L n;
    public final androidx.compose.ui.text.L o;

    public Y4(androidx.compose.ui.text.L l, androidx.compose.ui.text.L l2, androidx.compose.ui.text.L l3, androidx.compose.ui.text.L l4, androidx.compose.ui.text.L l5, androidx.compose.ui.text.L l6, androidx.compose.ui.text.L l7, androidx.compose.ui.text.L l8, androidx.compose.ui.text.L l9, androidx.compose.ui.text.L l10, androidx.compose.ui.text.L l11, androidx.compose.ui.text.L l12, androidx.compose.ui.text.L l13, androidx.compose.ui.text.L l14, androidx.compose.ui.text.L l15) {
        this.a = l;
        this.b = l2;
        this.c = l3;
        this.d = l4;
        this.e = l5;
        this.f = l6;
        this.g = l7;
        this.h = l8;
        this.i = l9;
        this.j = l10;
        this.k = l11;
        this.l = l12;
        this.m = l13;
        this.n = l14;
        this.o = l15;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Y4)) {
            return false;
        }
        Y4 y4 = (Y4) obj;
        return Intrinsics.b(this.a, y4.a) && Intrinsics.b(this.b, y4.b) && Intrinsics.b(this.c, y4.c) && Intrinsics.b(this.d, y4.d) && Intrinsics.b(this.e, y4.e) && Intrinsics.b(this.f, y4.f) && Intrinsics.b(this.g, y4.g) && Intrinsics.b(this.h, y4.h) && Intrinsics.b(this.i, y4.i) && Intrinsics.b(this.j, y4.j) && Intrinsics.b(this.k, y4.k) && Intrinsics.b(this.l, y4.l) && Intrinsics.b(this.m, y4.m) && Intrinsics.b(this.n, y4.n) && Intrinsics.b(this.o, y4.o);
    }

    public final int hashCode() {
        return this.o.hashCode() + ((this.n.hashCode() + ((this.m.hashCode() + ((this.l.hashCode() + ((this.k.hashCode() + ((this.j.hashCode() + ((this.i.hashCode() + ((this.h.hashCode() + ((this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "Typography(displayLarge=" + this.a + ", displayMedium=" + this.b + ",displaySmall=" + this.c + ", headlineLarge=" + this.d + ", headlineMedium=" + this.e + ", headlineSmall=" + this.f + ", titleLarge=" + this.g + ", titleMedium=" + this.h + ", titleSmall=" + this.i + ", bodyLarge=" + this.j + ", bodyMedium=" + this.k + ", bodySmall=" + this.l + ", labelLarge=" + this.m + ", labelMedium=" + this.n + ", labelSmall=" + this.o + ')';
    }
}
