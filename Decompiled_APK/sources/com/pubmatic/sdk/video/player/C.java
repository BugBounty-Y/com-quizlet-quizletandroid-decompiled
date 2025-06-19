package com.pubmatic.sdk.video.player;

import com.pubmatic.sdk.video.player.C4070e;

/* loaded from: classes2.dex */
public class C implements Runnable {
    final /* synthetic */ C4070e.p a;

    public C(C4070e.p pVar) {
        this.a = pVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        if (C4070e.this.a != null) {
            C4070e.this.a.onResume();
        }
    }
}
