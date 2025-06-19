package org.jsoup.parser;

import java.io.IOException;

/* loaded from: classes3.dex */
public enum G0 extends e1 {
    public G0() {
        super("CharacterReferenceInRcdata", 3);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        C5136v0 c5136v0 = e1.c;
        int[] iArrB = n.b(null, false);
        if (iArrB == null) {
            n.e('&');
        } else {
            n.g(new String(iArrB, 0, iArrB.length));
        }
        n.o(c5136v0);
    }
}
