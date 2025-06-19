package org.jsoup.nodes;

import java.io.IOException;

/* loaded from: classes3.dex */
public class p extends m {
    public p(String str) {
        this.d = str;
    }

    public static boolean G(StringBuilder sb) {
        return sb.length() != 0 && sb.charAt(sb.length() - 1) == ' ';
    }

    @Override // org.jsoup.nodes.n
    /* renamed from: F, reason: merged with bridge method [inline-methods] */
    public p i() {
        return (p) super.i();
    }

    @Override // org.jsoup.nodes.n
    public String r() {
        return "#text";
    }

    @Override // org.jsoup.nodes.n
    public void t(StringBuilder sb, int i, f fVar) throws IOException {
        boolean z;
        boolean z2;
        boolean z3 = fVar.e;
        n nVar = this.a;
        i iVar = nVar instanceof i ? (i) nVar : null;
        boolean z4 = z3 && !i.P(nVar);
        if (z4) {
            boolean z5 = (this.b == 0 && iVar != null && iVar.d.c) || (this.a instanceof g);
            boolean z6 = q() == null && iVar != null && iVar.d.c;
            n nVarQ = q();
            if ((((nVarQ instanceof i) && ((i) nVarQ).T(fVar)) || ((nVarQ instanceof p) && org.jsoup.internal.a.d(((p) nVarQ).D()))) && org.jsoup.internal.a.d(D())) {
                return;
            }
            if (this.b == 0 && iVar != null && iVar.d.d && !org.jsoup.internal.a.d(D())) {
                n.p(sb, i, fVar);
            }
            z = z5;
            z2 = z6;
        } else {
            z = false;
            z2 = false;
        }
        k.b(sb, D(), fVar, false, z4, z, z2);
    }

    @Override // org.jsoup.nodes.n
    public final String toString() {
        return s();
    }

    @Override // org.jsoup.nodes.n
    public void u(StringBuilder sb, int i, f fVar) {
    }
}
