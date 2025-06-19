package org.jsoup.nodes;

import java.io.IOException;

/* loaded from: classes3.dex */
public final class h extends m {
    public h(String str, String str2, String str3) {
        org.jsoup.helper.b.g(str);
        org.jsoup.helper.b.g(str2);
        org.jsoup.helper.b.g(str3);
        B("name", str);
        B("publicId", str2);
        B("systemId", str3);
        if (F("publicId")) {
            B("pubSysKey", "PUBLIC");
        } else if (F("systemId")) {
            B("pubSysKey", "SYSTEM");
        }
    }

    public final boolean F(String str) {
        return !org.jsoup.internal.a.d(d(str));
    }

    @Override // org.jsoup.nodes.n
    public final String r() {
        return "#doctype";
    }

    @Override // org.jsoup.nodes.n
    public final void t(StringBuilder sb, int i, f fVar) throws IOException {
        if (this.b > 0 && fVar.e) {
            sb.append('\n');
        }
        if (fVar.h != 1 || F("publicId") || F("systemId")) {
            sb.append("<!DOCTYPE");
        } else {
            sb.append("<!doctype");
        }
        if (F("name")) {
            sb.append(" ").append(d("name"));
        }
        if (F("pubSysKey")) {
            sb.append(" ").append(d("pubSysKey"));
        }
        if (F("publicId")) {
            sb.append(" \"").append(d("publicId")).append('\"');
        }
        if (F("systemId")) {
            sb.append(" \"").append(d("systemId")).append('\"');
        }
        sb.append('>');
    }

    @Override // org.jsoup.nodes.n
    public final void u(StringBuilder sb, int i, f fVar) {
    }
}
