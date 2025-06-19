package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public class zzdwf extends Exception {
    public final int a;

    public zzdwf(int i) {
        this.a = i;
    }

    public zzdwf(int i, String str) {
        super(str);
        this.a = i;
    }

    public zzdwf(String str, Throwable th) {
        super(str, th);
        this.a = 1;
    }
}
