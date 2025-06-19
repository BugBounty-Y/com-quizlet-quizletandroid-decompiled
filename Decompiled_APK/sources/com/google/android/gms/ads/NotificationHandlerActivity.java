package com.google.android.gms.ads;

import android.app.Activity;
import android.os.Bundle;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.C1592f;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.google.android.gms.internal.ads.InterfaceC2783wb;

/* loaded from: classes2.dex */
public final class NotificationHandlerActivity extends Activity {
    @Override // android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        try {
            C1608n c1608n = C1614q.f.b;
            BinderC2739va binderC2739va = new BinderC2739va();
            c1608n.getClass();
            InterfaceC2783wb interfaceC2783wb = (InterfaceC2783wb) new C1592f(this, binderC2739va).d(this, false);
            if (interfaceC2783wb == null) {
                com.google.android.gms.ads.internal.util.client.i.e("OfflineUtils is null");
            } else {
                interfaceC2783wb.l0(getIntent());
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.e("RemoteException calling handleNotificationIntent: ".concat(e.toString()));
        }
    }

    @Override // android.app.Activity
    public final void onResume() {
        super.onResume();
        finish();
    }
}
