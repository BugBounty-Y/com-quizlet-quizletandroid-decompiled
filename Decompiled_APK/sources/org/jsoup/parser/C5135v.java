package org.jsoup.parser;

/* renamed from: org.jsoup.parser.v, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5135v extends B {
    public C5135v() {
        super("InHeadNoscript", 4);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (bVar.h()) {
            c5096b.o(this);
            return true;
        }
        if (bVar.k() && ((L) bVar).d.equals("html")) {
            C5139x c5139x = B.g;
            c5096b.g = bVar;
            return c5139x.c(bVar, c5096b);
        }
        boolean zJ = bVar.j();
        C5133u c5133u = B.d;
        if (zJ && ((K) bVar).d.equals("noscript")) {
            c5096b.H();
            c5096b.l = c5133u;
            return true;
        }
        if (B.a(bVar) || bVar.g() || (bVar.k() && org.jsoup.internal.a.c(((L) bVar).d, A.f))) {
            c5096b.g = bVar;
            return c5133u.c(bVar, c5096b);
        }
        if (bVar.j() && ((K) bVar).d.equals("br")) {
            c5096b.o(this);
            G g = new G();
            g.c = bVar.toString();
            c5096b.z(g);
            return true;
        }
        if ((bVar.k() && org.jsoup.internal.a.c(((L) bVar).d, A.I)) || bVar.j()) {
            c5096b.o(this);
            return false;
        }
        c5096b.o(this);
        G g2 = new G();
        g2.c = bVar.toString();
        c5096b.z(g2);
        return true;
    }
}
