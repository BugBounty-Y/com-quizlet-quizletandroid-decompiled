package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.w0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5138w0 extends e1 {
    public C5138w0() {
        super("AttributeValue_unquoted", 39);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        String strK = c5094a.k(e1.A1);
        if (strK.length() > 0) {
            n.k.w(strK);
        }
        char cE = c5094a.e();
        if (cE == 0) {
            n.m(this);
            n.k.v((char) 65533);
            return;
        }
        if (cE != ' ') {
            if (cE != '\"' && cE != '`') {
                Z z = e1.a;
                if (cE == 65535) {
                    n.l(this);
                    n.o(z);
                    return;
                }
                if (cE != '\t' && cE != '\n' && cE != '\f' && cE != '\r') {
                    if (cE == '&') {
                        int[] iArrB = n.b('>', true);
                        if (iArrB != null) {
                            n.k.x(iArrB);
                            return;
                        } else {
                            n.k.v('&');
                            return;
                        }
                    }
                    if (cE != '\'') {
                        switch (cE) {
                            case '<':
                            case '=':
                                break;
                            case '>':
                                n.k();
                                n.o(z);
                                break;
                            default:
                                n.k.v(cE);
                                break;
                        }
                        return;
                    }
                }
            }
            n.m(this);
            n.k.v(cE);
            return;
        }
        n.o(e1.H);
    }
}
