package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.RemoteException;

/* renamed from: com.google.android.gms.internal.ads.ye, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2872ye implements Runnable {
    public final /* synthetic */ BinderC2915ze a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ boolean e;

    public /* synthetic */ RunnableC2872ye(BinderC2915ze binderC2915ze, int i, int i2, boolean z, boolean z2) {
        this.a = binderC2915ze;
        this.b = i;
        this.c = i2;
        this.d = z;
        this.e = z2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r11v0 */
    /* JADX WARN: Type inference failed for: r11v1 */
    /* JADX WARN: Type inference failed for: r11v2 */
    /* JADX WARN: Type inference failed for: r12v0 */
    /* JADX WARN: Type inference failed for: r12v1 */
    /* JADX WARN: Type inference failed for: r12v2 */
    /* JADX WARN: Type inference failed for: r2v1 */
    /* JADX WARN: Type inference failed for: r2v2 */
    /* JADX WARN: Type inference failed for: r2v3 */
    /* JADX WARN: Type inference failed for: r2v4 */
    /* JADX WARN: Type inference failed for: r2v8 */
    /* JADX WARN: Type inference failed for: r2v9 */
    /* JADX WARN: Type inference failed for: r3v2 */
    /* JADX WARN: Type inference failed for: r3v3 */
    /* JADX WARN: Type inference failed for: r3v5 */
    @Override // java.lang.Runnable
    public final void run() {
        int i;
        ?? r11;
        ?? r3;
        com.google.android.gms.ads.internal.client.w0 w0Var;
        com.google.android.gms.ads.internal.client.w0 w0Var2;
        com.google.android.gms.ads.internal.client.w0 w0Var3;
        BinderC2915ze binderC2915ze = this.a;
        int i2 = this.b;
        int i3 = this.c;
        boolean z = this.d;
        boolean z2 = this.e;
        synchronized (binderC2915ze.b) {
            try {
                boolean z3 = binderC2915ze.g;
                if (z3 || i3 != 1) {
                    i = i3;
                    r11 = false;
                } else {
                    i3 = 1;
                    i = 1;
                    r11 = true;
                }
                ?? r2 = i2 != i3;
                if (r2 == true && i == 1) {
                    r3 = true;
                    i = 1;
                } else {
                    r3 = false;
                }
                ?? r12 = r2 == true && i == 2;
                ?? r22 = r2 == true && i == 3;
                binderC2915ze.g = z3 || r11 == true;
                if (r11 != false) {
                    try {
                        com.google.android.gms.ads.internal.client.w0 w0Var4 = binderC2915ze.f;
                        if (w0Var4 != null) {
                            w0Var4.zzi();
                        }
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
                    }
                }
                if (r3 != false && (w0Var3 = binderC2915ze.f) != null) {
                    w0Var3.d4(2, w0Var3.f3());
                }
                if (r12 != false && (w0Var2 = binderC2915ze.f) != null) {
                    w0Var2.h();
                }
                if (r22 != false) {
                    com.google.android.gms.ads.internal.client.w0 w0Var5 = binderC2915ze.f;
                    if (w0Var5 != null) {
                        w0Var5.zze();
                    }
                    binderC2915ze.a.G();
                }
                if (z != z2 && (w0Var = binderC2915ze.f) != null) {
                    Parcel parcelF3 = w0Var.f3();
                    ClassLoader classLoader = AbstractC2857y5.a;
                    parcelF3.writeInt(z2 ? 1 : 0);
                    w0Var.d4(5, parcelF3);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
