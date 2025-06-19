package org.jsoup.parser;

/* renamed from: org.jsoup.parser.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5118m extends B {
    public C5118m() {
        super("Initial", 0);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (B.a(bVar)) {
            return true;
        }
        if (bVar.g()) {
            c5096b.A((H) bVar);
            return true;
        }
        boolean zH = bVar.h();
        C5129s c5129s = B.b;
        if (!zH) {
            c5096b.l = c5129s;
            return c5096b.e(bVar);
        }
        I i = (I) bVar;
        org.jsoup.nodes.h hVar = new org.jsoup.nodes.h(c5096b.h.b(i.c.toString()), i.e.toString(), i.f.toString());
        String str = i.d;
        if (str != null) {
            hVar.B("pubSysKey", str);
        }
        c5096b.d.B(hVar);
        if (i.g) {
            c5096b.d.l = 2;
        }
        c5096b.l = c5129s;
        return true;
    }
}
