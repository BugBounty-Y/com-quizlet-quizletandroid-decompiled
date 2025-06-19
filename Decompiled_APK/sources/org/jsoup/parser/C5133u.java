package org.jsoup.parser;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: org.jsoup.parser.u, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5133u extends B {
    public C5133u() {
        super("InHead", 3);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (B.a(bVar)) {
            c5096b.z((G) bVar);
            return true;
        }
        int iK = AbstractC0147y.k(bVar.b);
        if (iK == 0) {
            c5096b.o(this);
            return false;
        }
        if (iK != 1) {
            if (iK != 2) {
                if (iK != 3) {
                    c5096b.f("head");
                    return c5096b.e(bVar);
                }
                c5096b.A((H) bVar);
                return true;
            }
            String str = ((K) bVar).d;
            if (str.equals("head")) {
                c5096b.H();
                c5096b.l = B.f;
                return true;
            }
            if (org.jsoup.internal.a.c(str, A.c)) {
                c5096b.f("head");
                return c5096b.e(bVar);
            }
            if (!str.equals("template")) {
                c5096b.o(this);
                return false;
            }
            if (!c5096b.F(str)) {
                c5096b.o(this);
                return true;
            }
            c5096b.q(true);
            if (!str.equals(c5096b.a().d.b)) {
                c5096b.o(this);
            }
            c5096b.I(str);
            c5096b.l();
            c5096b.J();
            c5096b.P();
            return true;
        }
        L l = (L) bVar;
        String str2 = l.d;
        if (str2.equals("html")) {
            return B.g.c(bVar, c5096b);
        }
        if (org.jsoup.internal.a.c(str2, A.a)) {
            org.jsoup.nodes.i iVarB = c5096b.B(l);
            if (str2.equals("base") && iVarB.n("href") && !c5096b.n) {
                String strB = iVarB.b("href");
                if (strB.length() != 0) {
                    c5096b.f = strB;
                    c5096b.n = true;
                    org.jsoup.nodes.g gVar = c5096b.d;
                    gVar.getClass();
                    gVar.J(strB);
                }
            }
            return true;
        }
        if (str2.equals("meta")) {
            c5096b.B(l);
            return true;
        }
        boolean zEquals = str2.equals("title");
        C5141y c5141y = B.h;
        if (zEquals) {
            c5096b.c.o(e1.c);
            c5096b.m = c5096b.l;
            c5096b.l = c5141y;
            c5096b.y(l);
            return true;
        }
        if (org.jsoup.internal.a.c(str2, A.b)) {
            B.b(l, c5096b);
            return true;
        }
        if (str2.equals("noscript")) {
            c5096b.y(l);
            c5096b.l = B.e;
            return true;
        }
        if (str2.equals("script")) {
            c5096b.c.o(e1.f);
            c5096b.m = c5096b.l;
            c5096b.l = c5141y;
            c5096b.y(l);
            return true;
        }
        if (str2.equals("head")) {
            c5096b.o(this);
            return false;
        }
        if (!str2.equals("template")) {
            c5096b.f("head");
            return c5096b.e(bVar);
        }
        c5096b.y(l);
        c5096b.r.add(null);
        c5096b.v = false;
        C5114k c5114k = B.r;
        c5096b.l = c5114k;
        c5096b.L(c5114k);
        return true;
    }
}
