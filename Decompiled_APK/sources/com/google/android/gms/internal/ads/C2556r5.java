package com.google.android.gms.internal.ads;

import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;

/* renamed from: com.google.android.gms.internal.ads.r5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2556r5 {
    public final Z4 a;
    public final String b;
    public final String c;
    public final Class[] e;
    public volatile Method d = null;
    public final CountDownLatch f = new CountDownLatch(1);

    public C2556r5(Z4 z4, String str, String str2, Class... clsArr) {
        this.a = z4;
        this.b = str;
        this.c = str2;
        this.e = clsArr;
        z4.b.submit(new RunnableC1989e(this, 5));
    }
}
