package com.pubmatic.sdk.video.player;

import com.pubmatic.sdk.video.player.C4070e;

/* loaded from: classes2.dex */
public class x implements Runnable {
    final /* synthetic */ C4070e.a a;

    public x(C4070e.a aVar) {
        this.a = aVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        if (C4070e.this.a != null) {
            C4070e.this.a.onStop();
        }
    }
}
