package com.pubmatic.sdk.video.player;

/* loaded from: classes2.dex */
public class A implements Runnable {
    final /* synthetic */ B a;

    public A(B b) {
        this.a = b;
    }

    @Override // java.lang.Runnable
    public void run() {
        if (C4070e.this.a != null) {
            C4070e.this.a.onProgressUpdate(C4070e.this.g);
        }
    }
}
