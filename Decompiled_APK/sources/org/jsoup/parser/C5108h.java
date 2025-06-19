package org.jsoup.parser;

/* renamed from: org.jsoup.parser.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5108h extends B {
    public C5108h() {
        super("InCell", 14);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        boolean zJ = bVar.j();
        C5139x c5139x = B.g;
        if (!zJ) {
            if (!bVar.k() || !org.jsoup.internal.a.c(((L) bVar).d, A.y)) {
                c5096b.g = bVar;
                return c5139x.c(bVar, c5096b);
            }
            if (!c5096b.x("td") && !c5096b.x("th")) {
                c5096b.o(this);
                return false;
            }
            if (c5096b.x("td")) {
                c5096b.f("td");
            } else {
                c5096b.f("th");
            }
            return c5096b.e(bVar);
        }
        String str = ((K) bVar).d;
        if (org.jsoup.internal.a.c(str, A.v)) {
            boolean zX = c5096b.x(str);
            C5106g c5106g = B.n;
            if (!zX) {
                c5096b.o(this);
                c5096b.l = c5106g;
                return false;
            }
            c5096b.q(false);
            if (!c5096b.b(str)) {
                c5096b.o(this);
            }
            c5096b.I(str);
            c5096b.l();
            c5096b.l = c5106g;
            return true;
        }
        if (org.jsoup.internal.a.c(str, A.w)) {
            c5096b.o(this);
            return false;
        }
        if (!org.jsoup.internal.a.c(str, A.x)) {
            c5096b.g = bVar;
            return c5139x.c(bVar, c5096b);
        }
        if (!c5096b.x(str)) {
            c5096b.o(this);
            return false;
        }
        if (c5096b.x("td")) {
            c5096b.f("td");
        } else {
            c5096b.f("th");
        }
        return c5096b.e(bVar);
    }
}
