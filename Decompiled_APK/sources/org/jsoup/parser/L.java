package org.jsoup.parser;

import com.j256.ormlite.stmt.query.SimpleComparison;

/* loaded from: classes3.dex */
public final class L extends M {
    public L() {
        this.b = 2;
    }

    @Override // org.jsoup.parser.M, androidx.sqlite.db.b
    /* renamed from: D */
    public final M q() {
        super.q();
        this.m = null;
        return this;
    }

    @Override // androidx.sqlite.db.b
    public final String toString() {
        if (!z() || this.m.a <= 0) {
            StringBuilder sb = new StringBuilder(SimpleComparison.LESS_THAN_OPERATION);
            String str = this.c;
            return android.support.v4.media.session.a.t(sb, str != null ? str : "[unset]", SimpleComparison.GREATER_THAN_OPERATION);
        }
        StringBuilder sb2 = new StringBuilder(SimpleComparison.LESS_THAN_OPERATION);
        String str2 = this.c;
        sb2.append(str2 != null ? str2 : "[unset]");
        sb2.append(" ");
        sb2.append(this.m.toString());
        sb2.append(SimpleComparison.GREATER_THAN_OPERATION);
        return sb2.toString();
    }
}
