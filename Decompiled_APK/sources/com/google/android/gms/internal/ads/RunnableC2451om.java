package com.google.android.gms.internal.ads;

import android.view.View;

/* renamed from: com.google.android.gms.internal.ads.om, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2451om implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Hr b;
    public final /* synthetic */ View c;

    public /* synthetic */ RunnableC2451om(Hr hr, View view, int i) {
        this.a = i;
        this.b = hr;
        this.c = view;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.k5)).booleanValue() && AbstractC1972di.M.b) {
                    Jr jr = Jr.a;
                    Hr hr = this.b;
                    if (!hr.f) {
                        hr.b.a(this.c, jr);
                        break;
                    }
                }
                break;
            default:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.k5)).booleanValue() && AbstractC1972di.M.b) {
                    this.b.b(this.c);
                    break;
                }
                break;
        }
    }
}
