package org.jsoup.parser;

import com.j256.ormlite.stmt.query.SimpleComparison;

/* loaded from: classes3.dex */
public final class I extends androidx.sqlite.db.b {
    public final StringBuilder c;
    public String d;
    public final StringBuilder e;
    public final StringBuilder f;
    public boolean g;

    public I() {
        super(4);
        this.c = new StringBuilder();
        this.d = null;
        this.e = new StringBuilder();
        this.f = new StringBuilder();
        this.g = false;
        this.b = 1;
    }

    @Override // androidx.sqlite.db.b
    public final void q() {
        androidx.sqlite.db.b.r(this.c);
        this.d = null;
        androidx.sqlite.db.b.r(this.e);
        androidx.sqlite.db.b.r(this.f);
        this.g = false;
    }

    @Override // androidx.sqlite.db.b
    public final String toString() {
        return "<!doctype " + this.c.toString() + SimpleComparison.GREATER_THAN_OPERATION;
    }
}
