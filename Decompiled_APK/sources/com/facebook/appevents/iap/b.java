package com.facebook.appevents.iap;

import android.content.ComponentName;
import android.content.Context;
import android.content.ServiceConnection;
import android.os.IBinder;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b implements ServiceConnection {
    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName name, IBinder service) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(service, "service");
        AtomicBoolean atomicBoolean = d.a;
        Context context = com.facebook.o.a();
        o oVar = o.a;
        Object objH = null;
        if (!com.facebook.internal.instrument.crashshield.a.b(o.class)) {
            try {
                Intrinsics.checkNotNullParameter(context, "context");
                objH = o.a.h(context, "com.android.vending.billing.IInAppBillingService$Stub", "asInterface", null, new Object[]{service});
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(o.class, th);
            }
        }
        d.g = objH;
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName name) {
        Intrinsics.checkNotNullParameter(name, "name");
    }
}
