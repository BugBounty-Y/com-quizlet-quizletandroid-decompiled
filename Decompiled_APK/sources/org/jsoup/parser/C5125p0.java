package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.p0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5125p0 extends e1 {
    public C5125p0() {
        super("BeforeAttributeName", 33);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        char cE = c5094a.e();
        C5127q0 c5127q0 = e1.I;
        if (cE == 0) {
            c5094a.y();
            n.m(this);
            n.k.C();
            n.o(c5127q0);
            return;
        }
        if (cE != ' ') {
            if (cE != '\"' && cE != '\'') {
                if (cE == '/') {
                    n.o(e1.X);
                    return;
                }
                Z z = e1.a;
                if (cE == 65535) {
                    n.l(this);
                    n.o(z);
                    return;
                }
                if (cE == '\t' || cE == '\n' || cE == '\f' || cE == '\r') {
                    return;
                }
                switch (cE) {
                    case '<':
                        c5094a.y();
                        n.m(this);
                        break;
                    case '=':
                        break;
                    case '>':
                        break;
                    default:
                        n.k.C();
                        c5094a.y();
                        n.o(c5127q0);
                        return;
                }
                n.k();
                n.o(z);
                return;
            }
            n.m(this);
            n.k.C();
            M m = n.k;
            m.g = true;
            String str = m.f;
            StringBuilder sb = m.e;
            if (str != null) {
                sb.append(str);
                m.f = null;
            }
            sb.append(cE);
            n.o(c5127q0);
        }
    }
}
