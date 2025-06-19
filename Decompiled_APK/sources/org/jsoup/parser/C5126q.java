package org.jsoup.parser;

/* renamed from: org.jsoup.parser.q, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5126q extends B {
    public C5126q() {
        super("AfterAfterFrameset", 22);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (bVar.g()) {
            c5096b.A((H) bVar);
            return true;
        }
        if (bVar.h() || B.a(bVar) || (bVar.k() && ((L) bVar).d.equals("html"))) {
            C5139x c5139x = B.g;
            c5096b.g = bVar;
            return c5139x.c(bVar, c5096b);
        }
        if (bVar.i()) {
            return true;
        }
        if (!bVar.k() || !((L) bVar).d.equals("noframes")) {
            c5096b.o(this);
            return false;
        }
        C5133u c5133u = B.d;
        c5096b.g = bVar;
        return c5133u.c(bVar, c5096b);
    }
}
