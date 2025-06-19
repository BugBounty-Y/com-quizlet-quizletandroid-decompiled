package com.google.android.gms.ads;

import android.app.IntentService;
import android.content.Intent;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.C1592f;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.google.android.gms.internal.ads.InterfaceC2783wb;

/* loaded from: classes2.dex */
public class AdService extends IntentService {
    public AdService() {
        super("AdService");
    }

    @Override // android.app.IntentService
    public final void onHandleIntent(Intent intent) {
        try {
            C1608n c1608n = C1614q.f.b;
            BinderC2739va binderC2739va = new BinderC2739va();
            c1608n.getClass();
            ((InterfaceC2783wb) new C1592f(this, binderC2739va).d(this, false)).l0(intent);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.e("RemoteException calling handleNotificationIntent: ".concat(e.toString()));
        }
    }
}
