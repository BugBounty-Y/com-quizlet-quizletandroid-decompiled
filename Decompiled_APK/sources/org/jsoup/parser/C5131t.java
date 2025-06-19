package org.jsoup.parser;

/* renamed from: org.jsoup.parser.t, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5131t extends B {
    public C5131t() {
        super("BeforeHead", 2);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (B.a(bVar)) {
            c5096b.z((G) bVar);
            return true;
        }
        if (bVar.g()) {
            c5096b.A((H) bVar);
            return true;
        }
        if (bVar.h()) {
            c5096b.o(this);
            return false;
        }
        if (bVar.k() && ((L) bVar).d.equals("html")) {
            return B.g.c(bVar, c5096b);
        }
        if (bVar.k()) {
            L l = (L) bVar;
            if (l.d.equals("head")) {
                c5096b.o = c5096b.y(l);
                c5096b.l = B.d;
                return true;
            }
        }
        if (bVar.j() && org.jsoup.internal.a.c(((K) bVar).d, A.e)) {
            c5096b.g("head");
            return c5096b.e(bVar);
        }
        if (bVar.j()) {
            c5096b.o(this);
            return false;
        }
        c5096b.g("head");
        return c5096b.e(bVar);
    }
}
