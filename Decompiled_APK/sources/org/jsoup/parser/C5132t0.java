package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.t0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5132t0 extends e1 {
    public C5132t0() {
        super("AttributeValue_doubleQuoted", 37);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        String strF = c5094a.f(false);
        if (strF.length() > 0) {
            n.k.w(strF);
        } else {
            n.k.k = true;
        }
        char cE = c5094a.e();
        if (cE == 0) {
            n.m(this);
            n.k.v((char) 65533);
            return;
        }
        if (cE == '\"') {
            n.o(e1.W);
            return;
        }
        if (cE != '&') {
            if (cE != 65535) {
                n.k.v(cE);
                return;
            } else {
                n.l(this);
                n.o(e1.a);
                return;
            }
        }
        int[] iArrB = n.b('\"', true);
        if (iArrB != null) {
            n.k.x(iArrB);
        } else {
            n.k.v('&');
        }
    }
}
