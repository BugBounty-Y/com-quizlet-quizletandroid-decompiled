package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.y0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5142y0 extends e1 {
    public C5142y0() {
        super("SelfClosingStartTag", 41);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        Z z = e1.a;
        if (cE == '>') {
            n.k.l = true;
            n.k();
            n.o(z);
        } else if (cE == 65535) {
            n.l(this);
            n.o(z);
        } else {
            c5094a.y();
            n.m(this);
            n.o(e1.H);
        }
    }
}
