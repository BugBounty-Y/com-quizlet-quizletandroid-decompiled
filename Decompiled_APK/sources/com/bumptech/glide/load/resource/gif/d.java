package com.bumptech.glide.load.resource.gif;

import android.graphics.Bitmap;
import android.graphics.drawable.Drawable;
import android.os.Handler;

/* loaded from: classes.dex */
public final class d extends com.bumptech.glide.request.target.b {
    public final Handler d;
    public final int e;
    public final long f;
    public Bitmap g;

    public d(Handler handler, int i, long j) {
        this.d = handler;
        this.e = i;
        this.f = j;
    }

    @Override // com.bumptech.glide.request.target.e
    public final void a(Object obj) {
        this.g = (Bitmap) obj;
        Handler handler = this.d;
        handler.sendMessageAtTime(handler.obtainMessage(1, this), this.f);
    }

    @Override // com.bumptech.glide.request.target.e
    public final void h(Drawable drawable) {
        this.g = null;
    }
}
