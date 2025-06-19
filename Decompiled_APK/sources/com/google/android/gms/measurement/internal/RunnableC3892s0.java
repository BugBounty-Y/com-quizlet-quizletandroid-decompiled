package com.google.android.gms.measurement.internal;

import android.os.Bundle;
import androidx.appcompat.view.menu.RunnableC0069f;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONException;

/* renamed from: com.google.android.gms.measurement.internal.s0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC3892s0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ AtomicReference b;
    public final /* synthetic */ D0 c;

    public /* synthetic */ RunnableC3892s0(D0 d0, AtomicReference atomicReference, int i) {
        this.a = i;
        this.c = d0;
        this.b = atomicReference;
    }

    @Override // java.lang.Runnable
    public final void run() throws JSONException {
        switch (this.a) {
            case 0:
                D0 d0 = this.c;
                O o = ((Y) d0.b).h;
                Y.h(o);
                Bundle bundleH = o.p.h();
                Y0 y0E = Z.e((Y) d0.b);
                int i = 18;
                y0E.i0(new RunnableC0069f(i, y0E, this.b, y0E.f0(false), bundleH, false));
                return;
            case 1:
                AtomicReference atomicReference = this.b;
                synchronized (atomicReference) {
                    try {
                        try {
                            Y y = (Y) this.c.b;
                            atomicReference.set(Boolean.valueOf(y.g.f0(y.n().X(), AbstractC3893t.Z)));
                        } finally {
                        }
                    } finally {
                    }
                }
                return;
            case 2:
                AtomicReference atomicReference2 = this.b;
                synchronized (atomicReference2) {
                    try {
                        try {
                            Y y2 = (Y) this.c.b;
                            atomicReference2.set(Long.valueOf(y2.g.a0(y2.n().X(), AbstractC3893t.b0)));
                        } finally {
                        }
                    } finally {
                    }
                }
                return;
            default:
                AtomicReference atomicReference3 = this.b;
                synchronized (atomicReference3) {
                    try {
                        try {
                            Y y3 = (Y) this.c.b;
                            atomicReference3.set(Double.valueOf(y3.g.X(y3.n().X(), AbstractC3893t.d0)));
                        } finally {
                        }
                    } finally {
                    }
                }
                return;
        }
    }
}
