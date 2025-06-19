package org.jsoup.parser;

/* loaded from: classes3.dex */
public enum U extends e1 {
    public U() {
        super("RawtextEndTagOpen", 14);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) {
        V v = e1.p;
        R0 r0 = e1.e;
        if (c5094a.t()) {
            n.c(false);
            n.o(v);
        } else {
            n.g("</");
            n.o(r0);
        }
    }
}
