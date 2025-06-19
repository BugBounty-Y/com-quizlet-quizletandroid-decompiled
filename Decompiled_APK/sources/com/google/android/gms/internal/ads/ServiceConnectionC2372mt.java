package com.google.android.gms.internal.ads;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;

/* renamed from: com.google.android.gms.internal.ads.mt, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class ServiceConnectionC2372mt implements ServiceConnection {
    public final /* synthetic */ Tm a;

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        Tm tm = this.a;
        ((Gw) tm.d).c("LmdServiceConnectionManager.onServiceConnected(%s)", componentName);
        tm.c(new RunnableC2793wl(15, this, iBinder));
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        Tm tm = this.a;
        ((Gw) tm.d).c("LmdServiceConnectionManager.onServiceDisconnected(%s)", componentName);
        tm.c(new RunnableC2104gj(this, 21));
    }
}
