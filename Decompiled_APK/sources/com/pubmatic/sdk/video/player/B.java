package com.pubmatic.sdk.video.player;

import com.pubmatic.sdk.video.player.C4070e;

/* loaded from: classes2.dex */
public class B implements Runnable {
    final /* synthetic */ C4070e.l a;

    public B(C4070e.l lVar) {
        this.a = lVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        if (C4070e.this.b != null) {
            C4070e c4070e = C4070e.this;
            c4070e.g = c4070e.b.getCurrentPosition();
        }
        C4070e.this.e.post(new A(this));
    }
}
