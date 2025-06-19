package org.jsoup.parser;

/* renamed from: org.jsoup.parser.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5124p extends B {
    public C5124p() {
        super("AfterAfterBody", 21);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (bVar.g()) {
            c5096b.A((H) bVar);
            return true;
        }
        boolean zH = bVar.h();
        C5139x c5139x = B.g;
        if (zH || (bVar.k() && ((L) bVar).d.equals("html"))) {
            c5096b.g = bVar;
            return c5139x.c(bVar, c5096b);
        }
        if (B.a(bVar)) {
            c5096b.z((G) bVar);
            return true;
        }
        if (bVar.i()) {
            return true;
        }
        c5096b.o(this);
        if (!c5096b.F("body")) {
            c5096b.e.add(c5096b.d.V());
        }
        c5096b.l = c5139x;
        return c5096b.e(bVar);
    }
}
