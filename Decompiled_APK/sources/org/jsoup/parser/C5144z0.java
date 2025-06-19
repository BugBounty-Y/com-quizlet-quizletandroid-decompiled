package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.z0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5144z0 extends e1 {
    public C5144z0() {
        super("BogusComment", 42);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        n.n.w(c5094a.i('>'));
        char cL = c5094a.l();
        if (cL == '>' || cL == 65535) {
            c5094a.e();
            n.i();
            n.o(e1.a);
        }
    }
}
