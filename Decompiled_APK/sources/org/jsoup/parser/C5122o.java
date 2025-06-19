package org.jsoup.parser;

/* renamed from: org.jsoup.parser.o, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5122o extends B {
    public C5122o() {
        super("AfterFrameset", 20);
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
            C5139x c5139x = B.g;
            c5096b.g = bVar;
            return c5139x.c(bVar, c5096b);
        }
        if (bVar.j() && ((K) bVar).d.equals("html")) {
            c5096b.l = B.w;
            return true;
        }
        if (bVar.k() && ((L) bVar).d.equals("noframes")) {
            C5133u c5133u = B.d;
            c5096b.g = bVar;
            return c5133u.c(bVar, c5096b);
        }
        if (bVar.i()) {
            return true;
        }
        c5096b.o(this);
        return false;
    }
}
