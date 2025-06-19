package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum b1 extends e1 {
    public b1() {
        super("PLAINTEXT", 6);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cL = c5094a.l();
        if (cL == 0) {
            n.m(this);
            c5094a.a();
            n.e((char) 65533);
        } else if (cL != 65535) {
            n.g(c5094a.i((char) 0));
        } else {
            n.f(new J());
        }
    }
}
