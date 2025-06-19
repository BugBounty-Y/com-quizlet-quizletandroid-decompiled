package com.facebook.appevents.ondeviceprocessing;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;
import java.util.concurrent.CountDownLatch;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d implements ServiceConnection {
    public final CountDownLatch a = new CountDownLatch(1);
    public IBinder b;

    @Override // android.content.ServiceConnection
    public final void onNullBinding(ComponentName name) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a.countDown();
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName name, IBinder serviceBinder) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(serviceBinder, "serviceBinder");
        this.b = serviceBinder;
        this.a.countDown();
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName name) {
        Intrinsics.checkNotNullParameter(name, "name");
    }
}
