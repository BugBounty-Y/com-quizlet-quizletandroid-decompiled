package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.l0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5117l0 extends e1 {
    public C5117l0() {
        super("ScriptDataDoubleEscapedDash", 29);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        C5113j0 c5113j0 = e1.C;
        if (cE == 0) {
            n.m(this);
            n.e((char) 65533);
            n.o(c5113j0);
        } else if (cE == '-') {
            n.e(cE);
            n.o(e1.E);
        } else if (cE == '<') {
            n.e(cE);
            n.o(e1.F);
        } else if (cE != 65535) {
            n.e(cE);
            n.o(c5113j0);
        } else {
            n.l(this);
            n.o(e1.a);
        }
    }
}
