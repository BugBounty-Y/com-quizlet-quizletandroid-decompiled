package org.jsoup.parser;

/* loaded from: classes3.dex */
public final class H extends androidx.sqlite.db.b {
    public final StringBuilder c;
    public String d;
    public boolean e;

    public H() {
        super(4);
        this.c = new StringBuilder();
        this.e = false;
        this.b = 4;
    }

    @Override // androidx.sqlite.db.b
    public final void q() {
        androidx.sqlite.db.b.r(this.c);
        this.d = null;
        this.e = false;
    }

    @Override // androidx.sqlite.db.b
    public final String toString() {
        StringBuilder sb = new StringBuilder("<!--");
        String string = this.d;
        if (string == null) {
            string = this.c.toString();
        }
        return android.support.v4.media.session.a.t(sb, string, "-->");
    }

    public final void v(char c) {
        String str = this.d;
        StringBuilder sb = this.c;
        if (str != null) {
            sb.append(str);
            this.d = null;
        }
        sb.append(c);
    }

    public final void w(String str) {
        String str2 = this.d;
        StringBuilder sb = this.c;
        if (str2 != null) {
            sb.append(str2);
            this.d = null;
        }
        if (sb.length() == 0) {
            this.d = str;
        } else {
            sb.append(str);
        }
    }
}
