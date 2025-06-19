package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.k0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5115k0 extends e1 {
    public C5115k0() {
        super("CharacterReferenceInData", 1);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        Z z = e1.a;
        int[] iArrB = n.b(null, false);
        if (iArrB == null) {
            n.e('&');
        } else {
            n.g(new String(iArrB, 0, iArrB.length));
        }
        n.o(z);
    }
}
