package com.pubmatic.sdk.video.player;

import com.pubmatic.sdk.video.player.C4070e;

/* loaded from: classes2.dex */
public class z implements Runnable {
    final /* synthetic */ C4070e.k a;

    public z(C4070e.k kVar) {
        this.a = kVar;
    }

    @Override // java.lang.Runnable
    public void run() throws IllegalStateException {
        if (C4070e.this.b != null) {
            C4070e.this.b.stop();
        }
    }
}
