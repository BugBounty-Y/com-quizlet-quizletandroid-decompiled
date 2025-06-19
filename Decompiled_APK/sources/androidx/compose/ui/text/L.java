package androidx.compose.ui.text;

import androidx.compose.animation.d0;
import androidx.compose.material3.internal.AbstractC0646j;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class L {
    public static final L d = new L(0, 0, null, null, null, 0, 0, 0, 16777215);
    public final D a;
    public final t b;
    public final y c;

    public L(D d2, t tVar, y yVar) {
        this.a = d2;
        this.b = tVar;
        this.c = yVar;
    }

    public static L a(L l, androidx.compose.ui.graphics.I i) {
        float fA = l.a.a.a();
        D d2 = l.a;
        long j = d2.b;
        androidx.compose.ui.text.font.u uVar = d2.c;
        androidx.compose.ui.text.font.q qVar = d2.d;
        androidx.compose.ui.text.font.r rVar = d2.e;
        androidx.compose.ui.text.font.j jVar = d2.f;
        String str = d2.g;
        long j2 = d2.h;
        androidx.compose.ui.text.style.a aVar = d2.i;
        androidx.compose.ui.text.style.o oVar = d2.j;
        androidx.compose.ui.text.intl.b bVar = d2.k;
        long j3 = d2.l;
        androidx.compose.ui.text.style.j jVar2 = d2.m;
        U u = d2.n;
        androidx.compose.ui.graphics.drawscope.e eVar = d2.p;
        t tVar = l.b;
        int i2 = tVar.a;
        int i3 = tVar.b;
        long j4 = tVar.c;
        androidx.compose.ui.text.style.p pVar = tVar.d;
        y yVar = l.c;
        androidx.compose.ui.text.style.g gVar = tVar.f;
        int i4 = tVar.g;
        int i5 = tVar.h;
        androidx.compose.ui.text.style.q qVar2 = tVar.i;
        l.getClass();
        D d3 = new D(new androidx.compose.ui.text.style.b(i, fA), j, uVar, qVar, rVar, jVar, str, j2, aVar, oVar, bVar, j3, jVar2, u, yVar != null ? yVar.a : null, eVar);
        w wVar = null;
        if (yVar != null) {
            wVar = yVar.b;
        }
        return new L(d3, new t(i2, i3, j4, pVar, wVar, gVar, i4, i5, qVar2), yVar);
    }

    public static L b(L l, long j, long j2, androidx.compose.ui.text.font.u uVar, androidx.compose.ui.text.font.j jVar, long j3, int i, long j4, androidx.compose.ui.text.style.g gVar, int i2) {
        U u;
        long j5;
        y yVar = AbstractC0646j.a;
        long jB = (i2 & 1) != 0 ? l.a.a.b() : j;
        long j6 = (i2 & 2) != 0 ? l.a.b : j2;
        androidx.compose.ui.text.font.u uVar2 = (i2 & 4) != 0 ? l.a.c : uVar;
        D d2 = l.a;
        androidx.compose.ui.text.font.q qVar = d2.d;
        androidx.compose.ui.text.font.r rVar = d2.e;
        androidx.compose.ui.text.font.j jVar2 = (i2 & 32) != 0 ? d2.f : jVar;
        String str = d2.g;
        long j7 = (i2 & 128) != 0 ? d2.h : j3;
        androidx.compose.ui.text.style.a aVar = d2.i;
        androidx.compose.ui.text.style.o oVar = d2.j;
        androidx.compose.ui.text.intl.b bVar = d2.k;
        long j8 = d2.l;
        androidx.compose.ui.text.style.j jVar3 = d2.m;
        U u2 = d2.n;
        androidx.compose.ui.graphics.drawscope.e eVar = d2.p;
        int i3 = (i2 & 32768) != 0 ? l.b.a : i;
        int i4 = (i2 & 65536) != 0 ? l.b.b : 4;
        if ((i2 & 131072) != 0) {
            u = u2;
            j5 = l.b.c;
        } else {
            u = u2;
            j5 = j4;
        }
        t tVar = l.b;
        androidx.compose.ui.text.style.p pVar = tVar.d;
        y yVar2 = (i2 & 524288) != 0 ? l.c : yVar;
        return new L(new D(C0861v.c(jB, d2.a.b()) ? d2.a : jB != 16 ? new androidx.compose.ui.text.style.c(jB) : androidx.compose.ui.text.style.l.a, j6, uVar2, qVar, rVar, jVar2, str, j7, aVar, oVar, bVar, j8, jVar3, u, yVar2 != null ? yVar2.a : null, eVar), new t(i3, i4, j5, pVar, yVar2 != null ? yVar2.b : null, (i2 & 1048576) != 0 ? tVar.f : gVar, tVar.g, tVar.h, tVar.i), yVar2);
    }

    public static L f(L l, long j, long j2, androidx.compose.ui.text.font.u uVar, androidx.compose.ui.text.font.j jVar, long j3, int i, long j4, int i2) {
        long j5 = (i2 & 2) != 0 ? androidx.compose.ui.unit.m.c : j2;
        androidx.compose.ui.text.font.u uVar2 = (i2 & 4) != 0 ? null : uVar;
        androidx.compose.ui.text.font.j jVar2 = (i2 & 32) != 0 ? null : jVar;
        long j6 = (i2 & 128) != 0 ? androidx.compose.ui.unit.m.c : j3;
        long j7 = C0861v.g;
        int i3 = (32768 & i2) != 0 ? Integer.MIN_VALUE : i;
        long j8 = (i2 & 131072) != 0 ? androidx.compose.ui.unit.m.c : j4;
        D dA = E.a(l.a, j, null, Float.NaN, j5, uVar2, null, null, jVar2, null, j6, null, null, null, j7, null, null, null, null);
        t tVarA = u.a(l.b, i3, Integer.MIN_VALUE, j8, null, null, null, 0, Integer.MIN_VALUE, null);
        return (l.a == dA && l.b == tVarA) ? l : new L(dA, tVarA);
    }

    public final long c() {
        return this.a.a.b();
    }

    public final boolean d(L l) {
        if (this != l) {
            return Intrinsics.b(this.b, l.b) && this.a.a(l.a);
        }
        return true;
    }

    public final L e(L l) {
        return (l == null || l.equals(d)) ? this : new L(this.a.c(l.a), this.b.a(l.b));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof L)) {
            return false;
        }
        L l = (L) obj;
        return Intrinsics.b(this.a, l.a) && Intrinsics.b(this.b, l.b) && Intrinsics.b(this.c, l.c);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        y yVar = this.c;
        return iHashCode + (yVar != null ? yVar.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TextStyle(color=");
        sb.append((Object) C0861v.i(c()));
        sb.append(", brush=");
        D d2 = this.a;
        sb.append(d2.a.c());
        sb.append(", alpha=");
        sb.append(d2.a.a());
        sb.append(", fontSize=");
        sb.append((Object) androidx.compose.ui.unit.m.d(d2.b));
        sb.append(", fontWeight=");
        sb.append(d2.c);
        sb.append(", fontStyle=");
        sb.append(d2.d);
        sb.append(", fontSynthesis=");
        sb.append(d2.e);
        sb.append(", fontFamily=");
        sb.append(d2.f);
        sb.append(", fontFeatureSettings=");
        sb.append(d2.g);
        sb.append(", letterSpacing=");
        sb.append((Object) androidx.compose.ui.unit.m.d(d2.h));
        sb.append(", baselineShift=");
        sb.append(d2.i);
        sb.append(", textGeometricTransform=");
        sb.append(d2.j);
        sb.append(", localeList=");
        sb.append(d2.k);
        sb.append(", background=");
        d0.x(d2.l, ", textDecoration=", sb);
        sb.append(d2.m);
        sb.append(", shadow=");
        sb.append(d2.n);
        sb.append(", drawStyle=");
        sb.append(d2.p);
        sb.append(", textAlign=");
        t tVar = this.b;
        sb.append((Object) androidx.compose.ui.text.style.i.a(tVar.a));
        sb.append(", textDirection=");
        sb.append((Object) androidx.compose.ui.text.style.k.a(tVar.b));
        sb.append(", lineHeight=");
        sb.append((Object) androidx.compose.ui.unit.m.d(tVar.c));
        sb.append(", textIndent=");
        sb.append(tVar.d);
        sb.append(", platformStyle=");
        sb.append(this.c);
        sb.append(", lineHeightStyle=");
        sb.append(tVar.f);
        sb.append(", lineBreak=");
        sb.append((Object) androidx.compose.ui.text.style.e.a(tVar.g));
        sb.append(", hyphens=");
        sb.append((Object) androidx.compose.ui.text.style.d.a(tVar.h));
        sb.append(", textMotion=");
        sb.append(tVar.i);
        sb.append(')');
        return sb.toString();
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public L(D d2, t tVar) {
        x xVar = d2.o;
        w wVar = tVar.e;
        this(d2, tVar, (xVar == null && wVar == null) ? null : new y(xVar, wVar));
    }

    public L(long j, long j2, androidx.compose.ui.text.font.u uVar, androidx.compose.ui.text.font.q qVar, androidx.compose.ui.text.font.m mVar, long j3, int i, long j4, int i2) {
        this(new D((i2 & 1) != 0 ? C0861v.g : j, (i2 & 2) != 0 ? androidx.compose.ui.unit.m.c : j2, (i2 & 4) != 0 ? null : uVar, (i2 & 8) != 0 ? null : qVar, (androidx.compose.ui.text.font.r) null, (i2 & 32) != 0 ? null : mVar, (String) null, (i2 & 128) != 0 ? androidx.compose.ui.unit.m.c : j3, (androidx.compose.ui.text.style.a) null, (androidx.compose.ui.text.style.o) null, (androidx.compose.ui.text.intl.b) null, C0861v.g, (androidx.compose.ui.text.style.j) null, (U) null, (x) null), new t((32768 & i2) != 0 ? Integer.MIN_VALUE : i, Integer.MIN_VALUE, (i2 & 131072) != 0 ? androidx.compose.ui.unit.m.c : j4, null, null, null, 0, Integer.MIN_VALUE, null), null);
    }
}
