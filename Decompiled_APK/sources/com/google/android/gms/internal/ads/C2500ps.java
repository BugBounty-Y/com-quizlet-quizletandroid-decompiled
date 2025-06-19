package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.DeadObjectException;
import android.os.HandlerThread;
import android.os.Parcel;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.InterfaceC1652b;
import com.google.android.gms.common.internal.InterfaceC1653c;
import java.util.concurrent.LinkedBlockingQueue;

/* renamed from: com.google.android.gms.internal.ads.ps, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2500ps implements InterfaceC1652b, InterfaceC1653c {
    public final C2886ys a;
    public final String b;
    public final String c;
    public final LinkedBlockingQueue d;
    public final HandlerThread e;
    public final androidx.browser.customtabs.k f;
    public final long g;
    public final int h;

    public C2500ps(Context context, int i, String str, String str2, androidx.browser.customtabs.k kVar) {
        this.b = str;
        this.h = i;
        this.c = str2;
        this.f = kVar;
        HandlerThread handlerThread = new HandlerThread("GassDGClient");
        this.e = handlerThread;
        handlerThread.start();
        this.g = System.currentTimeMillis();
        C2886ys c2886ys = new C2886ys(19621000, context, handlerThread.getLooper(), this, this);
        this.a = c2886ys;
        this.d = new LinkedBlockingQueue();
        c2886ys.c();
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public final void V(int i) throws InterruptedException {
        try {
            b(4011, this.g, null);
            this.d.put(new zzfpo());
        } catch (InterruptedException unused) {
        }
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public final void X() {
        C2929zs c2929zs;
        long j = this.g;
        HandlerThread handlerThread = this.e;
        try {
            c2929zs = (C2929zs) this.a.m();
        } catch (DeadObjectException | IllegalStateException unused) {
            c2929zs = null;
        }
        if (c2929zs != null) {
            try {
                zzfpm zzfpmVar = new zzfpm(this.b, this.c, 1, 1, this.h - 1);
                Parcel parcelF3 = c2929zs.f3();
                AbstractC2857y5.c(parcelF3, zzfpmVar);
                Parcel parcelY3 = c2929zs.Y3(3, parcelF3);
                zzfpo zzfpoVar = (zzfpo) AbstractC2857y5.a(parcelY3, zzfpo.CREATOR);
                parcelY3.recycle();
                b(5011, j, null);
                this.d.put(zzfpoVar);
            } finally {
                try {
                } finally {
                }
            }
        }
    }

    public final void a() {
        C2886ys c2886ys = this.a;
        if (c2886ys != null) {
            if (c2886ys.q() || c2886ys.r()) {
                c2886ys.e();
            }
        }
    }

    public final void b(int i, long j, Exception exc) {
        this.f.r(i, System.currentTimeMillis() - j, exc);
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1653c
    public final void f0(ConnectionResult connectionResult) throws InterruptedException {
        try {
            b(4012, this.g, null);
            this.d.put(new zzfpo());
        } catch (InterruptedException unused) {
        }
    }
}
