package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.v0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5136v0 extends e1 {
    public C5136v0() {
        super("Rcdata", 2);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cL = c5094a.l();
        if (cL == 0) {
            n.m(this);
            c5094a.a();
            n.e((char) 65533);
        } else if (cL == '&') {
            n.o(e1.d);
            n.a.a();
        } else if (cL == '<') {
            n.o(e1.k);
            n.a.a();
        } else if (cL != 65535) {
            n.g(c5094a.g());
        } else {
            n.f(new J());
        }
    }
}
