package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.x0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5140x0 extends e1 {
    public C5140x0() {
        super("AfterAttributeValue_quoted", 40);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        C5125p0 c5125p0 = e1.H;
        if (cE == '\t' || cE == '\n' || cE == '\f' || cE == '\r' || cE == ' ') {
            n.o(c5125p0);
            return;
        }
        if (cE == '/') {
            n.o(e1.X);
            return;
        }
        Z z = e1.a;
        if (cE == '>') {
            n.k();
            n.o(z);
        } else if (cE == 65535) {
            n.l(this);
            n.o(z);
        } else {
            c5094a.y();
            n.m(this);
            n.o(c5125p0);
        }
    }
}
