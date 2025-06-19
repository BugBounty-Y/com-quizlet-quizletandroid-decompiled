package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Binder;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.InterfaceC1652b;
import com.google.android.gms.common.internal.InterfaceC1653c;

/* loaded from: classes2.dex */
public abstract class Hl implements InterfaceC1652b, InterfaceC1653c {
    public final C2313ld a = new C2313ld();
    public final Object b = new Object();
    public boolean c = false;
    public boolean d = false;
    public zzbvl e;
    public C2172i6 f;

    public static void b(Context context, C2313ld c2313ld, Xv xv) {
        if (((Boolean) Q7.j.o()).booleanValue() || ((Boolean) Q7.h.o()).booleanValue()) {
            c2313ld.a(new Qv(0, c2313ld, new Wr(context)), xv);
        }
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public final void V(int i) {
        com.google.android.gms.ads.internal.util.client.i.d("Cannot connect to remote service, fallback to local instance.");
    }

    public final void a() {
        synchronized (this.b) {
            try {
                this.d = true;
                if (this.f.q() || this.f.r()) {
                    this.f.e();
                }
                Binder.flushPendingCommands();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void f0(ConnectionResult connectionResult) {
        com.google.android.gms.ads.internal.util.client.i.d("Disconnected from remote ad request service.");
        this.a.d(new zzdyq(1));
    }
}
