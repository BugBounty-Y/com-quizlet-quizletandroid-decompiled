package org.wordpress.aztec;

/* loaded from: classes3.dex */
public final class E implements org.jsoup.select.n {
    public StringBuilder a;

    public E(StringBuilder sb) {
        this.a = sb;
    }

    @Override // org.jsoup.select.n
    public void d(org.jsoup.nodes.n nVar, int i) {
        boolean z = nVar instanceof org.jsoup.nodes.p;
        StringBuilder sb = this.a;
        if (z) {
            org.jsoup.nodes.p pVar = (org.jsoup.nodes.p) nVar;
            String strD = pVar.D();
            if (org.jsoup.nodes.i.P(pVar.a) || (pVar instanceof org.jsoup.nodes.c)) {
                sb.append(strD);
                return;
            } else {
                org.jsoup.internal.a.a(strD, sb, org.jsoup.nodes.p.G(sb));
                return;
            }
        }
        if (nVar instanceof org.jsoup.nodes.i) {
            org.jsoup.nodes.i iVar = (org.jsoup.nodes.i) nVar;
            if (sb.length() > 0) {
                org.jsoup.parser.E e = iVar.d;
                if ((e.c || e.b.equals("br")) && !org.jsoup.nodes.p.G(sb)) {
                    sb.append(' ');
                }
            }
        }
    }

    @Override // org.jsoup.select.n
    public void i(org.jsoup.nodes.n nVar, int i) {
        if ((nVar instanceof org.jsoup.nodes.i) && ((org.jsoup.nodes.i) nVar).d.c && (nVar.q() instanceof org.jsoup.nodes.p)) {
            StringBuilder sb = this.a;
            if (org.jsoup.nodes.p.G(sb)) {
                return;
            }
            sb.append(' ');
        }
    }
}
