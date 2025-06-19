package com.facebook.internal;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.IInterface;
import com.google.android.gms.internal.measurement.C3086z;
import com.google.android.gms.measurement.internal.X;
import com.google.android.gms.measurement.internal.Y;
import java.io.Serializable;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.facebook.internal.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class ServiceConnectionC1547b implements ServiceConnection {
    public final /* synthetic */ int a;
    public final Serializable b;
    public final Object c;

    public ServiceConnectionC1547b(com.google.android.gms.measurement.internal.P p, String str) {
        this.a = 1;
        this.c = p;
        this.b = str;
    }

    private final void b(ComponentName componentName) {
    }

    public IBinder a() throws InterruptedException {
        if (((AtomicBoolean) this.b).compareAndSet(true, true)) {
            throw new IllegalStateException("Binder already consumed");
        }
        Object objTake = ((LinkedBlockingDeque) this.c).take();
        Intrinsics.checkNotNullExpressionValue(objTake, "queue.take()");
        return (IBinder) objTake;
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) throws InterruptedException {
        Object obj = this.c;
        switch (this.a) {
            case 0:
                if (iBinder != null) {
                    try {
                        ((LinkedBlockingDeque) obj).put(iBinder);
                        break;
                    } catch (InterruptedException unused) {
                        return;
                    }
                }
                break;
            default:
                com.google.android.gms.measurement.internal.P p = (com.google.android.gms.measurement.internal.P) obj;
                if (iBinder == null) {
                    com.google.android.gms.measurement.internal.I i = p.a.i;
                    Y.k(i);
                    i.j.f("Install Referrer connection returned with null binder");
                    break;
                } else {
                    try {
                        int i2 = com.google.android.gms.internal.measurement.A.a;
                        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.finsky.externalreferrer.IGetInstallReferrerService");
                        com.google.android.gms.internal.measurement.B c3086z = iInterfaceQueryLocalInterface instanceof com.google.android.gms.internal.measurement.B ? (com.google.android.gms.internal.measurement.B) iInterfaceQueryLocalInterface : new C3086z(iBinder, "com.google.android.finsky.externalreferrer.IGetInstallReferrerService", 4);
                        if (c3086z != null) {
                            Y y = p.a;
                            com.google.android.gms.measurement.internal.I i3 = y.i;
                            Y.k(i3);
                            i3.o.f("Install Referrer Service connected");
                            X x = y.j;
                            Y.k(x);
                            x.c0(new androidx.camera.core.impl.utils.futures.h(this, c3086z, this));
                            break;
                        } else {
                            com.google.android.gms.measurement.internal.I i4 = p.a.i;
                            Y.k(i4);
                            i4.j.f("Install Referrer Service implementation was not found");
                            break;
                        }
                    } catch (RuntimeException e) {
                        com.google.android.gms.measurement.internal.I i5 = p.a.i;
                        Y.k(i5);
                        i5.j.g("Exception occurred while calling Install Referrer API", e);
                        return;
                    }
                }
        }
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        switch (this.a) {
            case 0:
                break;
            default:
                com.google.android.gms.measurement.internal.I i = ((com.google.android.gms.measurement.internal.P) this.c).a.i;
                Y.k(i);
                i.o.f("Install Referrer Service disconnected");
                break;
        }
    }

    public ServiceConnectionC1547b() {
        this.a = 0;
        this.b = new AtomicBoolean(false);
        this.c = new LinkedBlockingDeque();
    }
}
