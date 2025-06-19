package org.jsoup.parser;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: org.jsoup.parser.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5104f extends B {
    public C5104f() {
        super("InTableBody", 12);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        int iK = AbstractC0147y.k(bVar.b);
        C5143z c5143z = B.i;
        if (iK == 1) {
            L l = (L) bVar;
            String str = l.d;
            if (str.equals("tr")) {
                c5096b.m("tbody", "tfoot", "thead", "template");
                c5096b.y(l);
                c5096b.l = B.n;
                return true;
            }
            if (org.jsoup.internal.a.c(str, A.v)) {
                c5096b.o(this);
                c5096b.g("tr");
                return c5096b.e(l);
            }
            if (org.jsoup.internal.a.c(str, A.B)) {
                return d(bVar, c5096b);
            }
            c5096b.g = bVar;
            return c5143z.c(bVar, c5096b);
        }
        if (iK != 2) {
            c5096b.g = bVar;
            return c5143z.c(bVar, c5096b);
        }
        String str2 = ((K) bVar).d;
        if (org.jsoup.internal.a.c(str2, A.H)) {
            if (!c5096b.x(str2)) {
                c5096b.o(this);
                return false;
            }
            c5096b.m("tbody", "tfoot", "thead", "template");
            c5096b.H();
            c5096b.l = c5143z;
            return true;
        }
        if (str2.equals("table")) {
            return d(bVar, c5096b);
        }
        if (org.jsoup.internal.a.c(str2, A.C)) {
            c5096b.o(this);
            return false;
        }
        c5096b.g = bVar;
        return c5143z.c(bVar, c5096b);
    }

    public final boolean d(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (!c5096b.x("tbody") && !c5096b.x("thead") && !c5096b.u("tfoot")) {
            c5096b.o(this);
            return false;
        }
        c5096b.m("tbody", "tfoot", "thead", "template");
        c5096b.f(c5096b.a().d.b);
        return c5096b.e(bVar);
    }
}
