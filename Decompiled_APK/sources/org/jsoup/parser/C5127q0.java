package org.jsoup.parser;

import java.io.IOException;

/* renamed from: org.jsoup.parser.q0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public enum C5127q0 extends e1 {
    public C5127q0() {
        super("AttributeName", 34);
    }

    @Override // org.jsoup.parser.e1
    public final void d(N n, C5094a c5094a) throws IOException {
        String strK = c5094a.k(e1.z1);
        M m = n.k;
        m.getClass();
        String strReplace = strK.replace((char) 0, (char) 65533);
        m.g = true;
        String str = m.f;
        StringBuilder sb = m.e;
        if (str != null) {
            sb.append(str);
            m.f = null;
        }
        if (sb.length() == 0) {
            m.f = strReplace;
        } else {
            sb.append(strReplace);
        }
        char cE = c5094a.e();
        if (cE == '\t' || cE == '\n' || cE == '\f' || cE == '\r' || cE == ' ') {
            n.o(e1.J);
            return;
        }
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
            switch (cE) {
                case '<':
                    break;
                case '=':
                    n.o(e1.K);
                    break;
                case '>':
                    n.k();
                    n.o(z);
                    break;
                default:
                    M m2 = n.k;
                    m2.g = true;
                    String str2 = m2.f;
                    StringBuilder sb2 = m2.e;
                    if (str2 != null) {
                        sb2.append(str2);
                        m2.f = null;
                    }
                    sb2.append(cE);
                    break;
            }
            return;
        }
        n.m(this);
        M m3 = n.k;
        m3.g = true;
        String str3 = m3.f;
        StringBuilder sb3 = m3.e;
        if (str3 != null) {
            sb3.append(str3);
            m3.f = null;
        }
        sb3.append(cE);
    }
}
