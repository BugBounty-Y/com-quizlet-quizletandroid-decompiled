package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.InterfaceC1609n0;
import com.google.android.gms.ads.internal.client.zzt;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class Mn implements Bh {
    public final AtomicReference a = new AtomicReference();

    @Override // com.google.android.gms.internal.ads.Bh
    public final void d(zzt zztVar) {
        Object obj = this.a.get();
        if (obj == null) {
            return;
        }
        try {
            ((InterfaceC1609n0) obj).R2(zztVar);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (NullPointerException e2) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e2);
        }
    }
}
