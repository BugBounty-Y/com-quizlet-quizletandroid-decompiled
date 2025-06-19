package org.jsoup.parser;

/* renamed from: org.jsoup.parser.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5120n extends B {
    public C5120n() {
        super("InFrameset", 19);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        L l;
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
        if (!bVar.k()) {
            if (bVar.j() && ((K) bVar).d.equals("frameset")) {
                if (c5096b.b("html")) {
                    c5096b.o(this);
                    return false;
                }
                c5096b.H();
                if (!c5096b.x && !c5096b.b("frameset")) {
                    c5096b.l = B.u;
                    return true;
                }
            } else {
                if (!bVar.i()) {
                    c5096b.o(this);
                    return false;
                }
                if (!c5096b.b("html")) {
                    c5096b.o(this);
                }
            }
            return true;
        }
        l = (L) bVar;
        String str = l.d;
        str.getClass();
        switch (str) {
            case "frameset":
                c5096b.y(l);
                break;
            case "html":
                C5139x c5139x = B.g;
                c5096b.g = l;
                break;
            case "frame":
                c5096b.B(l);
                break;
            case "noframes":
                C5133u c5133u = B.d;
                c5096b.g = l;
                break;
            default:
                c5096b.o(this);
                break;
        }
        return true;
    }
}
