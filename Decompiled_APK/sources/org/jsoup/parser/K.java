package org.jsoup.parser;

import com.j256.ormlite.stmt.query.SimpleComparison;

/* loaded from: classes3.dex */
public final class K extends M {
    public K() {
        this.b = 3;
    }

    @Override // androidx.sqlite.db.b
    public final String toString() {
        StringBuilder sb = new StringBuilder("</");
        String str = this.c;
        if (str == null) {
            str = "[unset]";
        }
        return android.support.v4.media.session.a.t(sb, str, SimpleComparison.GREATER_THAN_OPERATION);
    }
}
