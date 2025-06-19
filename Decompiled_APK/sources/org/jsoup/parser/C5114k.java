package org.jsoup.parser;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: org.jsoup.parser.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5114k extends B {
    public C5114k() {
        super("InTemplate", 17);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        int iK = AbstractC0147y.k(bVar.b);
        C5139x c5139x = B.g;
        if (iK != 0) {
            C5133u c5133u = B.d;
            if (iK == 1) {
                String str = ((L) bVar).d;
                if (org.jsoup.internal.a.c(str, A.K)) {
                    c5096b.K(bVar, c5133u);
                    return true;
                }
                if (org.jsoup.internal.a.c(str, A.L)) {
                    c5096b.J();
                    C5143z c5143z = B.i;
                    c5096b.L(c5143z);
                    c5096b.l = c5143z;
                    return c5096b.e(bVar);
                }
                if (str.equals("col")) {
                    c5096b.J();
                    C5102e c5102e = B.l;
                    c5096b.L(c5102e);
                    c5096b.l = c5102e;
                    return c5096b.e(bVar);
                }
                if (str.equals("tr")) {
                    c5096b.J();
                    C5104f c5104f = B.m;
                    c5096b.L(c5104f);
                    c5096b.l = c5104f;
                    return c5096b.e(bVar);
                }
                if (!str.equals("td") && !str.equals("th")) {
                    c5096b.J();
                    c5096b.L(c5139x);
                    c5096b.l = c5139x;
                    return c5096b.e(bVar);
                }
                c5096b.J();
                C5106g c5106g = B.n;
                c5096b.L(c5106g);
                c5096b.l = c5106g;
                return c5096b.e(bVar);
            }
            if (iK == 2) {
                if (((K) bVar).d.equals("template")) {
                    c5096b.K(bVar, c5133u);
                    return true;
                }
                c5096b.o(this);
                return false;
            }
            if (iK != 3 && iK != 4) {
                if (iK == 5 && c5096b.F("template")) {
                    c5096b.o(this);
                    c5096b.I("template");
                    c5096b.l();
                    c5096b.J();
                    c5096b.P();
                    if (c5096b.l != B.r && c5096b.s.size() < 12) {
                        return c5096b.e(bVar);
                    }
                }
                return true;
            }
        }
        c5096b.K(bVar, c5139x);
        return true;
    }
}
