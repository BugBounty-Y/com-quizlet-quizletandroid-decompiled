package com.pubmatic.sdk.common.utility;

import com.pubmatic.sdk.common.utility.i;

/* loaded from: classes2.dex */
public class p implements Runnable {
    final /* synthetic */ i.b a;

    public p(i.b bVar) {
        this.a = bVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        i.this.a();
    }
}
