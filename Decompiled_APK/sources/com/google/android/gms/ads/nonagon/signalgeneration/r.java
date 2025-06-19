package com.google.android.gms.ads.nonagon.signalgeneration;

import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.os.Looper;
import android.text.TextUtils;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.InterfaceC2618si;
import org.json.JSONException;

/* loaded from: classes2.dex */
public final class r implements InterfaceC2618si {
    public final k a;
    public final int b;
    public final String c;

    public r(k kVar, int i, String str) {
        this.a = kVar;
        this.b = i;
        this.c = str;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2618si
    public final void a(String str) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2618si
    public final void b(q qVar) throws JSONException, com.google.android.gms.internal.appset.d, InterruptedException, Resources.NotFoundException, PackageManager.NameNotFoundException, ClassNotFoundException {
        if (qVar == null || this.b != 2 || TextUtils.isEmpty(this.c)) {
            return;
        }
        com.google.common.util.concurrent.d dVar = new com.google.common.util.concurrent.d(18, this, qVar);
        com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
        if (Looper.getMainLooper().getThread() != Thread.currentThread()) {
            dVar.run();
        } else {
            AbstractC2270kd.a.execute(dVar);
        }
    }
}
