package org.jsoup.parser;

/* renamed from: org.jsoup.parser.w, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5137w extends B {
    public C5137w() {
        super("AfterHead", 5);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (B.a(bVar)) {
            c5096b.z((G) bVar);
        } else if (bVar.g()) {
            c5096b.A((H) bVar);
        } else if (bVar.h()) {
            c5096b.o(this);
        } else {
            boolean zK = bVar.k();
            C5133u c5133u = B.d;
            if (zK) {
                L l = (L) bVar;
                String str = l.d;
                boolean zEquals = str.equals("html");
                C5139x c5139x = B.g;
                if (zEquals) {
                    c5096b.g = bVar;
                    return c5139x.c(bVar, c5096b);
                }
                if (str.equals("body")) {
                    c5096b.y(l);
                    c5096b.v = false;
                    c5096b.l = c5139x;
                } else if (str.equals("frameset")) {
                    c5096b.y(l);
                    c5096b.l = B.t;
                } else if (org.jsoup.internal.a.c(str, A.g)) {
                    c5096b.o(this);
                    org.jsoup.nodes.i iVar = c5096b.o;
                    c5096b.e.add(iVar);
                    c5096b.K(bVar, c5133u);
                    c5096b.O(iVar);
                } else {
                    if (str.equals("head")) {
                        c5096b.o(this);
                        return false;
                    }
                    c5096b.g("body");
                    c5096b.v = true;
                    c5096b.e(bVar);
                }
            } else if (bVar.j()) {
                String str2 = ((K) bVar).d;
                if (org.jsoup.internal.a.c(str2, A.d)) {
                    c5096b.g("body");
                    c5096b.v = true;
                    c5096b.e(bVar);
                } else {
                    if (!str2.equals("template")) {
                        c5096b.o(this);
                        return false;
                    }
                    c5096b.K(bVar, c5133u);
                }
            } else {
                c5096b.g("body");
                c5096b.v = true;
                c5096b.e(bVar);
            }
        }
        return true;
    }
}
