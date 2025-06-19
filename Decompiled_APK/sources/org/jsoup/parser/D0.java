package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum D0 extends e1 {
    public D0() {
        super("Comment", 46);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cL = c5094a.l();
        if (cL == 0) {
            n.m(this);
            c5094a.a();
            n.n.v((char) 65533);
        } else if (cL == '-') {
            n.o(e1.f1);
            n.a.a();
        } else {
            if (cL != 65535) {
                n.n.w(c5094a.j('-', 0));
                return;
            }
            n.l(this);
            n.i();
            n.o(e1.a);
        }
    }
}
