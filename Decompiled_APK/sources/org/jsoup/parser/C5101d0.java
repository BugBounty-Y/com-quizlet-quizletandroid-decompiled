package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.d0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5101d0 extends e1 {
    public C5101d0() {
        super("ScriptDataEscapedDash", 22);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        if (c5094a.n()) {
            n.l(this);
            n.o(e1.a);
            return;
        }
        char cE = c5094a.e();
        C5099c0 c5099c0 = e1.v;
        if (cE == 0) {
            n.m(this);
            n.e((char) 65533);
            n.o(c5099c0);
        } else if (cE == '-') {
            n.e(cE);
            n.o(e1.x);
        } else if (cE == '<') {
            n.o(e1.y);
        } else {
            n.e(cE);
            n.o(c5099c0);
        }
    }
}
