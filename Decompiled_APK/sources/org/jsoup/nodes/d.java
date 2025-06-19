package org.jsoup.nodes;

import java.io.IOException;

/* loaded from: classes3.dex */
public final class d extends m {
    public d(String str) {
        this.d = str;
    }

    @Override // org.jsoup.nodes.n
    /* renamed from: clone */
    public final Object i() {
        return (d) super.i();
    }

    @Override // org.jsoup.nodes.n
    public final n i() {
        return (d) super.i();
    }

    @Override // org.jsoup.nodes.n
    public final String r() {
        return "#comment";
    }

    @Override // org.jsoup.nodes.n
    public final void t(StringBuilder sb, int i, f fVar) throws IOException {
        if (fVar.e && this.b == 0) {
            n nVar = this.a;
            if ((nVar instanceof i) && ((i) nVar).d.d) {
                n.p(sb, i, fVar);
            }
        }
        sb.append("<!--").append(D()).append("-->");
    }

    @Override // org.jsoup.nodes.n
    public final String toString() {
        return s();
    }

    @Override // org.jsoup.nodes.n
    public final void u(StringBuilder sb, int i, f fVar) {
    }
}
