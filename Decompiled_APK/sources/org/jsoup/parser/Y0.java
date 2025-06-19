package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum Y0 extends e1 {
    public Y0() {
        super("BogusDoctype", 65);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        Z z = e1.a;
        if (cE == '>') {
            n.j();
            n.o(z);
        } else {
            if (cE != 65535) {
                return;
            }
            n.j();
            n.o(z);
        }
    }
}
