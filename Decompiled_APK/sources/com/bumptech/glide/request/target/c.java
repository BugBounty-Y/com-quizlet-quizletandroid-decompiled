package com.bumptech.glide.request.target;

import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Looper;
import com.bumptech.glide.load.engine.y;
import com.bumptech.glide.m;

/* loaded from: classes.dex */
public final class c extends b {
    public static final Handler e = new Handler(Looper.getMainLooper(), new y(1));
    public final m d;

    public c(m mVar) {
        this.d = mVar;
    }

    @Override // com.bumptech.glide.request.target.e
    public final void a(Object obj) {
        com.bumptech.glide.request.c cVar = this.c;
        if (cVar == null || !cVar.i()) {
            return;
        }
        e.obtainMessage(1, this).sendToTarget();
    }

    @Override // com.bumptech.glide.request.target.e
    public final void h(Drawable drawable) {
    }
}
