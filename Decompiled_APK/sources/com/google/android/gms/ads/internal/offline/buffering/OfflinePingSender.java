package com.google.android.gms.ads.internal.offline.buffering;

import android.content.Context;
import android.os.RemoteException;
import androidx.annotation.NonNull;
import androidx.work.C1446u;
import androidx.work.Worker;
import androidx.work.WorkerParameters;
import androidx.work.x;
import com.google.android.gms.ads.internal.client.C1592f;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.google.android.gms.internal.ads.InterfaceC2783wb;

/* loaded from: classes2.dex */
public class OfflinePingSender extends Worker {
    public final InterfaceC2783wb e;

    public OfflinePingSender(@NonNull Context context, @NonNull WorkerParameters workerParameters) {
        super(context, workerParameters);
        C1608n c1608n = C1614q.f.b;
        BinderC2739va binderC2739va = new BinderC2739va();
        c1608n.getClass();
        this.e = (InterfaceC2783wb) new C1592f(context, binderC2739va).d(context, false);
    }

    @Override // androidx.work.Worker
    @NonNull
    public final x doWork() {
        try {
            this.e.g();
            return x.a();
        } catch (RemoteException unused) {
            return new C1446u();
        }
    }
}
