package com.google.android.gms.internal.ads;

import android.content.Context;
import android.database.ContentObserver;
import android.media.AudioManager;
import android.os.Handler;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class Nr extends ContentObserver {
    public final Context a;
    public final AudioManager b;
    public final AtomicReference c;
    public final Xr d;

    public Nr(Handler handler, Context context, Xr xr) {
        super(handler);
        this.c = new AtomicReference(Float.valueOf(-1.0f));
        this.a = context;
        this.b = (AudioManager) context.getSystemService("audio");
        this.d = xr;
    }

    @Override // android.database.ContentObserver
    public final void onChange(boolean z) {
        new Thread(new RunnableC2104gj(this, 16)).start();
    }
}
