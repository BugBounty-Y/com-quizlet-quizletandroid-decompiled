package androidx.compose.ui.text;

import androidx.compose.animation.d0;
import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class D {
    public final androidx.compose.ui.text.style.n a;
    public final long b;
    public final androidx.compose.ui.text.font.u c;
    public final androidx.compose.ui.text.font.q d;
    public final androidx.compose.ui.text.font.r e;
    public final androidx.compose.ui.text.font.j f;
    public final String g;
    public final long h;
    public final androidx.compose.ui.text.style.a i;
    public final androidx.compose.ui.text.style.o j;
    public final androidx.compose.ui.text.intl.b k;
    public final long l;
    public final androidx.compose.ui.text.style.j m;
    public final U n;
    public final x o;
    public final androidx.compose.ui.graphics.drawscope.e p;

    public D(long j, long j2, androidx.compose.ui.text.font.u uVar, androidx.compose.ui.text.font.q qVar, androidx.compose.ui.text.font.r rVar, androidx.compose.ui.text.font.j jVar, String str, long j3, androidx.compose.ui.text.style.a aVar, androidx.compose.ui.text.style.o oVar, androidx.compose.ui.text.intl.b bVar, long j4, androidx.compose.ui.text.style.j jVar2, U u, x xVar) {
        this(j != 16 ? new androidx.compose.ui.text.style.c(j) : androidx.compose.ui.text.style.l.a, j2, uVar, qVar, rVar, jVar, str, j3, aVar, oVar, bVar, j4, jVar2, u, xVar, null);
    }

    public final boolean a(D d) {
        if (this == d) {
            return true;
        }
        return androidx.compose.ui.unit.m.a(this.b, d.b) && Intrinsics.b(this.c, d.c) && Intrinsics.b(this.d, d.d) && Intrinsics.b(this.e, d.e) && Intrinsics.b(this.f, d.f) && Intrinsics.b(this.g, d.g) && androidx.compose.ui.unit.m.a(this.h, d.h) && Intrinsics.b(this.i, d.i) && Intrinsics.b(this.j, d.j) && Intrinsics.b(this.k, d.k) && C0861v.c(this.l, d.l) && Intrinsics.b(this.o, d.o);
    }

    public final boolean b(D d) {
        return Intrinsics.b(this.a, d.a) && Intrinsics.b(this.m, d.m) && Intrinsics.b(this.n, d.n) && Intrinsics.b(this.p, d.p);
    }

    public final D c(D d) {
        if (d == null) {
            return this;
        }
        androidx.compose.ui.text.style.n nVar = d.a;
        return E.a(this, nVar.b(), nVar.c(), nVar.a(), d.b, d.c, d.d, d.e, d.f, d.g, d.h, d.i, d.j, d.k, d.l, d.m, d.n, d.o, d.p);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof D)) {
            return false;
        }
        D d = (D) obj;
        return a(d) && b(d);
    }

    public final int hashCode() {
        androidx.compose.ui.text.style.n nVar = this.a;
        long jB = nVar.b();
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        int iHashCode = Long.hashCode(jB) * 31;
        AbstractC0857q abstractC0857qC = nVar.c();
        int iHashCode2 = (Float.hashCode(nVar.a()) + ((iHashCode + (abstractC0857qC != null ? abstractC0857qC.hashCode() : 0)) * 31)) * 31;
        androidx.compose.ui.unit.n[] nVarArr = androidx.compose.ui.unit.m.b;
        int iD = d0.d(iHashCode2, 31, this.b);
        androidx.compose.ui.text.font.u uVar = this.c;
        int i2 = (iD + (uVar != null ? uVar.a : 0)) * 31;
        androidx.compose.ui.text.font.q qVar = this.d;
        int iHashCode3 = (i2 + (qVar != null ? Integer.hashCode(qVar.a) : 0)) * 31;
        androidx.compose.ui.text.font.r rVar = this.e;
        int iHashCode4 = (iHashCode3 + (rVar != null ? Integer.hashCode(rVar.a) : 0)) * 31;
        androidx.compose.ui.text.font.j jVar = this.f;
        int iHashCode5 = (iHashCode4 + (jVar != null ? jVar.hashCode() : 0)) * 31;
        String str = this.g;
        int iD2 = d0.d((iHashCode5 + (str != null ? str.hashCode() : 0)) * 31, 31, this.h);
        androidx.compose.ui.text.style.a aVar = this.i;
        int iHashCode6 = (iD2 + (aVar != null ? Float.hashCode(aVar.a) : 0)) * 31;
        androidx.compose.ui.text.style.o oVar = this.j;
        int iHashCode7 = (iHashCode6 + (oVar != null ? oVar.hashCode() : 0)) * 31;
        androidx.compose.ui.text.intl.b bVar = this.k;
        int iD3 = d0.d((iHashCode7 + (bVar != null ? bVar.a.hashCode() : 0)) * 31, 31, this.l);
        androidx.compose.ui.text.style.j jVar2 = this.m;
        int i3 = (iD3 + (jVar2 != null ? jVar2.a : 0)) * 31;
        U u = this.n;
        int iHashCode8 = (i3 + (u != null ? u.hashCode() : 0)) * 31;
        x xVar = this.o;
        int iHashCode9 = (iHashCode8 + (xVar != null ? xVar.hashCode() : 0)) * 31;
        androidx.compose.ui.graphics.drawscope.e eVar = this.p;
        return iHashCode9 + (eVar != null ? eVar.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SpanStyle(color=");
        androidx.compose.ui.text.style.n nVar = this.a;
        sb.append((Object) C0861v.i(nVar.b()));
        sb.append(", brush=");
        sb.append(nVar.c());
        sb.append(", alpha=");
        sb.append(nVar.a());
        sb.append(", fontSize=");
        sb.append((Object) androidx.compose.ui.unit.m.d(this.b));
        sb.append(", fontWeight=");
        sb.append(this.c);
        sb.append(", fontStyle=");
        sb.append(this.d);
        sb.append(", fontSynthesis=");
        sb.append(this.e);
        sb.append(", fontFamily=");
        sb.append(this.f);
        sb.append(", fontFeatureSettings=");
        sb.append(this.g);
        sb.append(", letterSpacing=");
        sb.append((Object) androidx.compose.ui.unit.m.d(this.h));
        sb.append(", baselineShift=");
        sb.append(this.i);
        sb.append(", textGeometricTransform=");
        sb.append(this.j);
        sb.append(", localeList=");
        sb.append(this.k);
        sb.append(", background=");
        d0.x(this.l, ", textDecoration=", sb);
        sb.append(this.m);
        sb.append(", shadow=");
        sb.append(this.n);
        sb.append(", platformStyle=");
        sb.append(this.o);
        sb.append(", drawStyle=");
        sb.append(this.p);
        sb.append(')');
        return sb.toString();
    }

    public D(androidx.compose.ui.text.style.n nVar, long j, androidx.compose.ui.text.font.u uVar, androidx.compose.ui.text.font.q qVar, androidx.compose.ui.text.font.r rVar, androidx.compose.ui.text.font.j jVar, String str, long j2, androidx.compose.ui.text.style.a aVar, androidx.compose.ui.text.style.o oVar, androidx.compose.ui.text.intl.b bVar, long j3, androidx.compose.ui.text.style.j jVar2, U u, x xVar, androidx.compose.ui.graphics.drawscope.e eVar) {
        this.a = nVar;
        this.b = j;
        this.c = uVar;
        this.d = qVar;
        this.e = rVar;
        this.f = jVar;
        this.g = str;
        this.h = j2;
        this.i = aVar;
        this.j = oVar;
        this.k = bVar;
        this.l = j3;
        this.m = jVar2;
        this.n = u;
        this.o = xVar;
        this.p = eVar;
    }

    public D(long j, long j2, androidx.compose.ui.text.font.u uVar, androidx.compose.ui.text.font.q qVar, androidx.compose.ui.text.font.r rVar, androidx.compose.ui.text.font.j jVar, String str, long j3, androidx.compose.ui.text.style.a aVar, androidx.compose.ui.text.style.o oVar, androidx.compose.ui.text.intl.b bVar, long j4, androidx.compose.ui.text.style.j jVar2, U u, int i) {
        this((i & 1) != 0 ? C0861v.g : j, (i & 2) != 0 ? androidx.compose.ui.unit.m.c : j2, (i & 4) != 0 ? null : uVar, (i & 8) != 0 ? null : qVar, (i & 16) != 0 ? null : rVar, (i & 32) != 0 ? null : jVar, (i & 64) != 0 ? null : str, (i & 128) != 0 ? androidx.compose.ui.unit.m.c : j3, (i & 256) != 0 ? null : aVar, (i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? null : oVar, (i & 1024) != 0 ? null : bVar, (i & 2048) != 0 ? C0861v.g : j4, (i & 4096) != 0 ? null : jVar2, (i & 8192) != 0 ? null : u, (x) null);
    }
}
