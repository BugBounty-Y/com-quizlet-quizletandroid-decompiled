package com.google.android.gms.internal.ads;

import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import java.io.IOException;

/* loaded from: classes2.dex */
public final class Y4 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Z4 b;

    public /* synthetic */ Y4(Z4 z4, int i) {
        this.a = i;
        this.b = z4;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Z4 z4 = this.b;
                z4.getClass();
                try {
                    if (z4.f == null && z4.g) {
                        com.google.android.gms.ads.identifier.b bVar = new com.google.android.gms.ads.identifier.b(z4.a);
                        bVar.e(true);
                        z4.f = bVar;
                        break;
                    }
                } catch (GooglePlayServicesNotAvailableException | GooglePlayServicesRepairableException | IOException unused) {
                    z4.f = null;
                    return;
                }
                break;
            default:
                AbstractC2773w7.a(this.b.a);
                break;
        }
    }
}
