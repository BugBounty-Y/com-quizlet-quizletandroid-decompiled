package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum E0 extends e1 {
    public E0() {
        super("CommentEndDash", 47);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        D0 d0 = e1.e1;
        if (cE == 0) {
            n.m(this);
            H h = n.n;
            h.v('-');
            h.v((char) 65533);
            n.o(d0);
            return;
        }
        if (cE == '-') {
            n.o(e1.g1);
            return;
        }
        if (cE == 65535) {
            n.l(this);
            n.i();
            n.o(e1.a);
        } else {
            H h2 = n.n;
            h2.v('-');
            h2.v(cE);
            n.o(d0);
        }
    }
}
