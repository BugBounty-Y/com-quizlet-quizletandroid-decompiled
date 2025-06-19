package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.s0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5130s0 extends e1 {
    public C5130s0() {
        super("BeforeAttributeValue", 36);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        C5138w0 c5138w0 = e1.V;
        if (cE == 0) {
            n.m(this);
            n.k.v((char) 65533);
            n.o(c5138w0);
            return;
        }
        if (cE != ' ') {
            if (cE == '\"') {
                n.o(e1.L);
                return;
            }
            if (cE != '`') {
                Z z = e1.a;
                if (cE == 65535) {
                    n.l(this);
                    n.k();
                    n.o(z);
                    return;
                }
                if (cE == '\t' || cE == '\n' || cE == '\f' || cE == '\r') {
                    return;
                }
                if (cE == '&') {
                    c5094a.y();
                    n.o(c5138w0);
                    return;
                }
                if (cE == '\'') {
                    n.o(e1.M);
                    return;
                }
                switch (cE) {
                    case '<':
                    case '=':
                        break;
                    case '>':
                        n.m(this);
                        n.k();
                        n.o(z);
                        break;
                    default:
                        c5094a.y();
                        n.o(c5138w0);
                        break;
                }
                return;
            }
            n.m(this);
            n.k.v(cE);
            n.o(c5138w0);
        }
    }
}
