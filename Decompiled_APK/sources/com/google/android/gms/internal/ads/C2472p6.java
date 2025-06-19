package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.concurrent.ExecutorService;

/* renamed from: com.google.android.gms.internal.ads.p6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2472p6 {
    public B5 a;
    public boolean b;
    public final ExecutorService c;

    public C2472p6() {
        this.c = com.google.android.gms.ads.internal.util.client.a.b;
    }

    public C2472p6(Context context) {
        ExecutorService executorService = com.google.android.gms.ads.internal.util.client.a.b;
        this.c = executorService;
        executorService.execute(new Qv(6, this, context));
    }
}
