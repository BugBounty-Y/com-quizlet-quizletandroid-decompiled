package com.google.android.gms.measurement.internal;

import androidx.appcompat.view.menu.RunnableC0069f;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: com.google.android.gms.measurement.internal.u0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC3896u0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ AtomicReference b;
    public final /* synthetic */ D0 c;

    public /* synthetic */ RunnableC3896u0(D0 d0, AtomicReference atomicReference, int i) {
        this.a = i;
        this.c = d0;
        this.b = atomicReference;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Y0 y0R = ((Y) this.c.b).r();
                K0[] k0Arr = {K0.SGTM_CLIENT};
                ArrayList arrayList = new ArrayList(1);
                arrayList.add(Integer.valueOf(k0Arr[0].a));
                zzpc zzpcVar = new zzpc(arrayList);
                y0R.S();
                y0R.Q();
                int i = 19;
                y0R.i0(new RunnableC0069f(i, y0R, this.b, y0R.f0(false), zzpcVar, false));
                return;
            case 1:
                Y0 y0E = Z.e((Y) this.c.b);
                y0E.i0(new Q0(y0E, this.b, y0E.f0(false), 0));
                return;
            case 2:
                AtomicReference atomicReference = this.b;
                synchronized (atomicReference) {
                    try {
                        try {
                            Y y = (Y) this.c.b;
                            atomicReference.set(y.g.e0(y.n().X(), AbstractC3893t.a0));
                        } finally {
                        }
                    } finally {
                    }
                }
                return;
            default:
                AtomicReference atomicReference2 = this.b;
                synchronized (atomicReference2) {
                    try {
                        try {
                            Y y2 = (Y) this.c.b;
                            atomicReference2.set(Integer.valueOf(y2.g.Y(y2.n().X(), AbstractC3893t.c0)));
                        } finally {
                        }
                    } finally {
                    }
                }
                return;
        }
    }
}
