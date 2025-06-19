package org.jsoup.parser;

/* renamed from: org.jsoup.parser.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5112j extends B {
    public C5112j() {
        super("InSelectInTable", 16);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        boolean zK = bVar.k();
        String[] strArr = A.G;
        if (zK && org.jsoup.internal.a.c(((L) bVar).d, strArr)) {
            c5096b.o(this);
            c5096b.I("select");
            c5096b.P();
            return c5096b.e(bVar);
        }
        if (bVar.j()) {
            K k = (K) bVar;
            if (org.jsoup.internal.a.c(k.d, strArr)) {
                c5096b.o(this);
                if (!c5096b.x(k.d)) {
                    return false;
                }
                c5096b.I("select");
                c5096b.P();
                return c5096b.e(bVar);
            }
        }
        C5110i c5110i = B.p;
        c5096b.g = bVar;
        return c5110i.c(bVar, c5096b);
    }
}
