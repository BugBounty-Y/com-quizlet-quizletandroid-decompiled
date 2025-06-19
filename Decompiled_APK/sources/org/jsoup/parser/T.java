package org.jsoup.parser;

/* loaded from: classes3.dex */
public enum T extends e1 {
    public T() {
        super("RawtextLessthanSign", 13);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) {
        if (!c5094a.r('/')) {
            n.e('<');
            n.o(e1.e);
        } else {
            n.d();
            n.o(e1.o);
            n.a.a();
        }
    }
}
