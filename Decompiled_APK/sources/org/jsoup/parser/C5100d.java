package org.jsoup.parser;

/* renamed from: org.jsoup.parser.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5100d extends B {
    public C5100d() {
        super("InCaption", 10);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (bVar.j()) {
            K k = (K) bVar;
            if (k.d.equals("caption")) {
                if (!c5096b.x(k.d)) {
                    c5096b.o(this);
                    return false;
                }
                c5096b.q(false);
                if (!c5096b.b("caption")) {
                    c5096b.o(this);
                }
                c5096b.I("caption");
                c5096b.l();
                c5096b.l = B.i;
                return true;
            }
        }
        if ((bVar.k() && org.jsoup.internal.a.c(((L) bVar).d, A.y)) || (bVar.j() && ((K) bVar).d.equals("table"))) {
            c5096b.o(this);
            if (c5096b.f("caption")) {
                return c5096b.e(bVar);
            }
            return true;
        }
        if (bVar.j() && org.jsoup.internal.a.c(((K) bVar).d, A.J)) {
            c5096b.o(this);
            return false;
        }
        C5139x c5139x = B.g;
        c5096b.g = bVar;
        return c5139x.c(bVar, c5096b);
    }
}
