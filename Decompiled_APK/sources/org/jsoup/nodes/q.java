package org.jsoup.nodes;

import com.j256.ormlite.stmt.query.SimpleComparison;
import java.io.IOException;

/* loaded from: classes3.dex */
public final class q extends m {
    public final boolean e;

    public q(String str, boolean z) {
        org.jsoup.helper.b.g(str);
        this.d = str;
        this.e = z;
    }

    @Override // org.jsoup.nodes.n
    /* renamed from: clone */
    public final Object i() {
        return (q) super.i();
    }

    @Override // org.jsoup.nodes.n
    public final n i() {
        return (q) super.i();
    }

    @Override // org.jsoup.nodes.n
    public final String r() {
        return "#declaration";
    }

    @Override // org.jsoup.nodes.n
    public final void t(StringBuilder sb, int i, f fVar) throws IOException {
        Appendable appendableAppend = sb.append(SimpleComparison.LESS_THAN_OPERATION);
        boolean z = this.e;
        appendableAppend.append(z ? "!" : "?").append(D());
        b bVarE = e();
        bVarE.getClass();
        int i2 = 0;
        while (true) {
            if (i2 < bVarE.a && b.r(bVarE.b[i2])) {
                i2++;
            } else {
                if (i2 >= bVarE.a) {
                    break;
                }
                a aVar = new a(bVarE.b[i2], (String) bVarE.c[i2], bVarE);
                int i3 = i2 + 1;
                String str = aVar.a;
                String str2 = aVar.b;
                if (str2 == null) {
                    str2 = "";
                }
                if (!str.equals("#declaration")) {
                    sb.append(' ');
                    sb.append((CharSequence) str);
                    if (!str2.isEmpty()) {
                        sb.append("=\"");
                        k.b(sb, str2, fVar, true, false, false, false);
                        sb.append('\"');
                    }
                }
                i2 = i3;
            }
        }
        sb.append(z ? "!" : "?").append(SimpleComparison.GREATER_THAN_OPERATION);
    }

    @Override // org.jsoup.nodes.n
    public final String toString() {
        return s();
    }

    @Override // org.jsoup.nodes.n
    public final void u(StringBuilder sb, int i, f fVar) {
    }
}
