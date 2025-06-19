package org.jsoup.parser;

/* renamed from: org.jsoup.parser.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5106g extends B {
    public C5106g() {
        super("InRow", 13);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        boolean zK = bVar.k();
        C5143z c5143z = B.i;
        if (zK) {
            L l = (L) bVar;
            String str = l.d;
            if (org.jsoup.internal.a.c(str, A.v)) {
                c5096b.m("tr", "template");
                c5096b.y(l);
                c5096b.l = B.o;
                c5096b.r.add(null);
                return true;
            }
            if (!org.jsoup.internal.a.c(str, A.D)) {
                c5096b.g = bVar;
                return c5143z.c(bVar, c5096b);
            }
            if (c5096b.f("tr")) {
                return c5096b.e(bVar);
            }
            return false;
        }
        if (!bVar.j()) {
            c5096b.g = bVar;
            return c5143z.c(bVar, c5096b);
        }
        String str2 = ((K) bVar).d;
        boolean zEquals = str2.equals("tr");
        C5104f c5104f = B.m;
        if (zEquals) {
            if (!c5096b.x(str2)) {
                c5096b.o(this);
                return false;
            }
            c5096b.m("tr", "template");
            c5096b.H();
            c5096b.l = c5104f;
            return true;
        }
        if (str2.equals("table")) {
            if (c5096b.f("tr")) {
                return c5096b.e(bVar);
            }
            return false;
        }
        if (!org.jsoup.internal.a.c(str2, A.s)) {
            if (org.jsoup.internal.a.c(str2, A.E)) {
                c5096b.o(this);
                return false;
            }
            c5096b.g = bVar;
            return c5143z.c(bVar, c5096b);
        }
        if (!c5096b.x(str2) || !c5096b.x("tr")) {
            c5096b.o(this);
            return false;
        }
        c5096b.m("tr", "template");
        c5096b.H();
        c5096b.l = c5104f;
        return true;
    }
}
