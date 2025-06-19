package com.pubmatic.sdk.video.player;

import com.pubmatic.sdk.video.player.C4070e;

/* loaded from: classes2.dex */
public class D implements Runnable {
    final /* synthetic */ C4070e.q a;

    public D(C4070e.q qVar) {
        this.a = qVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        if (C4070e.this.a != null) {
            C4070e.this.a.onPause();
        }
    }
}
