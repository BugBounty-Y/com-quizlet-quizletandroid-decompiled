package org.jsoup.parser;

/* renamed from: org.jsoup.parser.s, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5129s extends B {
    public C5129s() {
        super("BeforeHtml", 1);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (bVar.h()) {
            c5096b.o(this);
            return false;
        }
        if (bVar.g()) {
            c5096b.A((H) bVar);
            return true;
        }
        if (B.a(bVar)) {
            c5096b.z((G) bVar);
            return true;
        }
        boolean zK = bVar.k();
        C5131t c5131t = B.c;
        if (zK) {
            L l = (L) bVar;
            if (l.d.equals("html")) {
                c5096b.y(l);
                c5096b.l = c5131t;
                return true;
            }
        }
        if (bVar.j() && org.jsoup.internal.a.c(((K) bVar).d, A.e)) {
            org.jsoup.nodes.i iVar = new org.jsoup.nodes.i(c5096b.i("html", c5096b.h), null, null);
            c5096b.E(iVar);
            c5096b.e.add(iVar);
            c5096b.l = c5131t;
            return c5096b.e(bVar);
        }
        if (bVar.j()) {
            c5096b.o(this);
            return false;
        }
        org.jsoup.nodes.i iVar2 = new org.jsoup.nodes.i(c5096b.i("html", c5096b.h), null, null);
        c5096b.E(iVar2);
        c5096b.e.add(iVar2);
        c5096b.l = c5131t;
        return c5096b.e(bVar);
    }
}
