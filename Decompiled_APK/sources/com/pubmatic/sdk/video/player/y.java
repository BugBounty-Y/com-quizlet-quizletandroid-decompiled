package com.pubmatic.sdk.video.player;

import com.pubmatic.sdk.video.player.C4070e;

/* loaded from: classes2.dex */
public class y implements Runnable {
    final /* synthetic */ C4070e.k a;

    public y(C4070e.k kVar) {
        this.a = kVar;
    }

    @Override // java.lang.Runnable
    public void run() {
        if (C4070e.this.a != null) {
            C4070e.this.a.onFailure(h.MEDIA_DISPLAY_ERROR, "MEDIA_DISPLAY_ERROR");
        }
    }
}
