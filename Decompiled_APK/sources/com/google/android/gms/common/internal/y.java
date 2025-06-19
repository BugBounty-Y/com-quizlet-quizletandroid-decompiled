package com.google.android.gms.common.internal;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.IInterface;

/* loaded from: classes2.dex */
public final class y implements ServiceConnection {
    public final int a;
    public final /* synthetic */ AbstractC1655e b;

    public y(AbstractC1655e abstractC1655e, int i) {
        this.b = abstractC1655e;
        this.a = i;
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        AbstractC1655e abstractC1655e = this.b;
        if (iBinder == null) {
            abstractC1655e.u();
            return;
        }
        synchronized (abstractC1655e.h) {
            try {
                IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.common.internal.IGmsServiceBroker");
                abstractC1655e.i = (iInterfaceQueryLocalInterface == null || !(iInterfaceQueryLocalInterface instanceof q)) ? new q(iBinder) : (q) iInterfaceQueryLocalInterface;
            } catch (Throwable th) {
                throw th;
            }
        }
        AbstractC1655e abstractC1655e2 = this.b;
        int i = this.a;
        abstractC1655e2.getClass();
        A a = new A(abstractC1655e2, 0, null);
        w wVar = abstractC1655e2.f;
        wVar.sendMessage(wVar.obtainMessage(7, i, -1, a));
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        AbstractC1655e abstractC1655e = this.b;
        synchronized (abstractC1655e.h) {
            abstractC1655e.i = null;
        }
        AbstractC1655e abstractC1655e2 = this.b;
        int i = this.a;
        w wVar = abstractC1655e2.f;
        wVar.sendMessage(wVar.obtainMessage(6, i, 1));
    }
}
