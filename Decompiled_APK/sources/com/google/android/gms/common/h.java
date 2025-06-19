package com.google.android.gms.common;

/* loaded from: classes2.dex */
public class h {
    public static final h c = new h(true, null, null);
    public final boolean a;
    public final Exception b;

    public h(boolean z, String str, Exception exc) {
        this.a = z;
        this.b = exc;
    }

    public static h b(String str) {
        return new h(false, str, null);
    }

    public static h c(String str, Exception exc) {
        return new h(false, str, exc);
    }

    public void a() {
    }
}
