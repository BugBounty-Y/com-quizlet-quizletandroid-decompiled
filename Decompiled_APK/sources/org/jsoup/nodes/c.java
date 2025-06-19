package org.jsoup.nodes;

import java.io.IOException;
import org.jsoup.UncheckedIOException;

/* loaded from: classes3.dex */
public final class c extends p {
    @Override // org.jsoup.nodes.p
    /* renamed from: F */
    public final p i() {
        return (c) super.i();
    }

    @Override // org.jsoup.nodes.p, org.jsoup.nodes.n
    /* renamed from: clone */
    public final Object i() {
        return (c) super.i();
    }

    @Override // org.jsoup.nodes.p, org.jsoup.nodes.n
    public final n i() {
        return (c) super.i();
    }

    @Override // org.jsoup.nodes.p, org.jsoup.nodes.n
    public final String r() {
        return "#cdata";
    }

    @Override // org.jsoup.nodes.p, org.jsoup.nodes.n
    public final void t(StringBuilder sb, int i, f fVar) throws IOException {
        sb.append("<![CDATA[").append(D());
    }

    @Override // org.jsoup.nodes.p, org.jsoup.nodes.n
    public final void u(StringBuilder sb, int i, f fVar) {
        try {
            sb.append("]]>");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
