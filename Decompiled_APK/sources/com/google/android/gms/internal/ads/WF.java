package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class WF {
    public final J9 a;
    public final int[] b;

    public WF(J9 j9, int[] iArr) {
        if (iArr.length == 0) {
            AbstractC2096gb.A("ETSDefinition", "Empty tracks are not allowed", new IllegalArgumentException());
        }
        this.a = j9;
        this.b = iArr;
    }
}
