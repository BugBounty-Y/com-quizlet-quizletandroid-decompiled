package com.pubmatic.sdk.video.player;

import android.view.View;

/* loaded from: classes2.dex */
public class E implements Runnable {
    final /* synthetic */ View a;

    public E(View view) {
        this.a = view;
    }

    @Override // java.lang.Runnable
    public void run() {
        this.a.setVisibility(4);
    }
}
