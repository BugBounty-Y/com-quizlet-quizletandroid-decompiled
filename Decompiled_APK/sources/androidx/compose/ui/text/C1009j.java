package androidx.compose.ui.text;

import androidx.compose.animation.d0;
import androidx.compose.ui.graphics.C0861v;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.text.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1009j {
    public final G a;

    public C1009j(G g) {
        this.a = g;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1009j)) {
            return false;
        }
        G g = this.a;
        C1009j c1009j = (C1009j) obj;
        if (!Intrinsics.b(g.a, c1009j.a.a)) {
            return false;
        }
        G g2 = c1009j.a;
        if (!g.b.d(g2.b) || !Intrinsics.b(g.c, g2.c) || g.d != g2.d || g.e != g2.e || g.f != g2.f || !Intrinsics.b(g.g, g2.g) || g.h != g2.h || g.i != g2.i) {
            return false;
        }
        long j = g.j;
        return androidx.compose.ui.unit.a.h(j) == androidx.compose.ui.unit.a.h(g2.j) && androidx.compose.ui.unit.a.g(j) == androidx.compose.ui.unit.a.g(g2.j);
    }

    public final int hashCode() {
        G g = this.a;
        int iHashCode = g.a.hashCode() * 31;
        L l = g.b;
        D d = l.a;
        d.getClass();
        androidx.compose.ui.unit.n[] nVarArr = androidx.compose.ui.unit.m.b;
        int iHashCode2 = Long.hashCode(d.b) * 31;
        androidx.compose.ui.text.font.u uVar = d.c;
        int i = (iHashCode2 + (uVar != null ? uVar.a : 0)) * 31;
        androidx.compose.ui.text.font.q qVar = d.d;
        int iHashCode3 = (i + (qVar != null ? Integer.hashCode(qVar.a) : 0)) * 31;
        androidx.compose.ui.text.font.r rVar = d.e;
        int iHashCode4 = (iHashCode3 + (rVar != null ? Integer.hashCode(rVar.a) : 0)) * 31;
        androidx.compose.ui.text.font.j jVar = d.f;
        int iHashCode5 = (iHashCode4 + (jVar != null ? jVar.hashCode() : 0)) * 31;
        String str = d.g;
        int iD = d0.d((iHashCode5 + (str != null ? str.hashCode() : 0)) * 31, 31, d.h);
        androidx.compose.ui.text.style.a aVar = d.i;
        int iHashCode6 = (iD + (aVar != null ? Float.hashCode(aVar.a) : 0)) * 31;
        androidx.compose.ui.text.style.o oVar = d.j;
        int iHashCode7 = (iHashCode6 + (oVar != null ? oVar.hashCode() : 0)) * 31;
        androidx.compose.ui.text.intl.b bVar = d.k;
        int iHashCode8 = (iHashCode7 + (bVar != null ? bVar.a.hashCode() : 0)) * 31;
        int i2 = C0861v.h;
        kotlin.C c = kotlin.D.b;
        int iD2 = d0.d(iHashCode8, 31, d.l);
        x xVar = d.o;
        int iHashCode9 = (l.b.hashCode() + ((iD2 + (xVar != null ? xVar.hashCode() : 0)) * 31)) * 31;
        y yVar = l.c;
        int iHashCode10 = (g.i.hashCode() + ((g.h.hashCode() + ((g.g.hashCode() + d0.b(g.f, d0.g((d0.f((iHashCode9 + (yVar != null ? yVar.hashCode() : 0) + iHashCode) * 31, 31, g.c) + g.d) * 31, 31, g.e), 31)) * 31)) * 31)) * 31;
        long j = g.j;
        return Integer.hashCode(androidx.compose.ui.unit.a.g(j)) + ((Integer.hashCode(androidx.compose.ui.unit.a.h(j)) + iHashCode10) * 31);
    }
}
