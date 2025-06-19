package com.google.android.gms.internal.ads;

import java.io.IOException;

/* loaded from: classes2.dex */
public class zzgh extends IOException {
    public final int a;

    public zzgh() {
        this.a = 2008;
    }

    public zzgh(String str, int i) {
        super(str);
        this.a = i;
    }

    public zzgh(String str, Exception exc, int i) {
        super(str, exc);
        this.a = i;
    }

    public zzgh(int i, Exception exc) {
        super(exc);
        this.a = i;
    }
}
