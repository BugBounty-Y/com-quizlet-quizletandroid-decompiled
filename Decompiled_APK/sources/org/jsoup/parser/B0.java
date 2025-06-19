package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum B0 extends e1 {
    public B0() {
        super("CommentStart", 44);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        D0 d0 = e1.e1;
        if (cE == 0) {
            n.m(this);
            n.n.v((char) 65533);
            n.o(d0);
            return;
        }
        if (cE == '-') {
            n.o(e1.d1);
            return;
        }
        Z z = e1.a;
        if (cE == '>') {
            n.m(this);
            n.i();
            n.o(z);
        } else if (cE != 65535) {
            c5094a.y();
            n.o(d0);
        } else {
            n.l(this);
            n.i();
            n.o(z);
        }
    }
}
