package org.jsoup.parser;

/* renamed from: org.jsoup.parser.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5116l extends B {
    public C5116l() {
        super("AfterBody", 18);
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
        boolean zK = bVar.k();
        C5139x c5139x = B.g;
        if (zK && ((L) bVar).d.equals("html")) {
            c5096b.g = bVar;
            return c5139x.c(bVar, c5096b);
        }
        if (bVar.j() && ((K) bVar).d.equals("html")) {
            if (c5096b.x) {
                c5096b.o(this);
                return false;
            }
            if (c5096b.F("html")) {
                c5096b.I("html");
            }
            c5096b.l = B.v;
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
