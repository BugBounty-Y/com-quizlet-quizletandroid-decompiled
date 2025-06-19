package org.jsoup.parser;

/* renamed from: org.jsoup.parser.y, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5141y extends B {
    public C5141y() {
        super("Text", 7);
    }

    @Override // org.jsoup.parser.B
    public final boolean c(androidx.sqlite.db.b bVar, C5096b c5096b) {
        if (bVar.b == 5) {
            c5096b.z((G) bVar);
            return true;
        }
        if (bVar.i()) {
            c5096b.o(this);
            c5096b.H();
            c5096b.l = c5096b.m;
            return c5096b.e(bVar);
        }
        if (!bVar.j()) {
            return true;
        }
        c5096b.H();
        c5096b.l = c5096b.m;
        return true;
    }
}
