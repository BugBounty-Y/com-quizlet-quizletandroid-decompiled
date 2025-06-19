package com.braze.lrucache;

import java.io.File;

/* loaded from: classes.dex */
public final class g {
    public final String a;
    public final long[] b;
    public boolean c;
    public d d;
    public final int e;
    public final File f;

    public g(String str, int i, File file) {
        this.a = str;
        this.e = i;
        this.f = file;
        this.b = new long[i];
    }

    public final File a(int i) {
        return new File(this.f, this.a + "." + i + ".tmp");
    }
}
