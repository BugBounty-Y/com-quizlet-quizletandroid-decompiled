package com.google.firebase.perf.application;

import android.app.Activity;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.SparseIntArray;
import androidx.core.app.WindowOnFrameMetricsAvailableListenerC1022i;
import androidx.webkit.internal.p;
import com.google.android.gms.cloudmessaging.k;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;

/* loaded from: classes2.dex */
public final class f {
    public static final com.google.firebase.perf.logging.a e = com.google.firebase.perf.logging.a.d();
    public final Activity a;
    public final p b;
    public final HashMap c;
    public boolean d;

    public f(Activity activity) {
        p pVar = new p(7);
        HashMap map = new HashMap();
        this.d = false;
        this.a = activity;
        this.b = pVar;
        this.c = map;
    }

    public final com.google.firebase.perf.util.d a() {
        boolean z = this.d;
        com.google.firebase.perf.logging.a aVar = e;
        if (!z) {
            aVar.a();
            return new com.google.firebase.perf.util.d();
        }
        SparseIntArray sparseIntArray = ((SparseIntArray[]) ((k) this.b.b).c)[0];
        if (sparseIntArray == null) {
            aVar.a();
            return new com.google.firebase.perf.util.d();
        }
        int i = 0;
        int i2 = 0;
        int i3 = 0;
        for (int i4 = 0; i4 < sparseIntArray.size(); i4++) {
            int iKeyAt = sparseIntArray.keyAt(i4);
            int iValueAt = sparseIntArray.valueAt(i4);
            i += iValueAt;
            if (iKeyAt > 700) {
                i3 += iValueAt;
            }
            if (iKeyAt > 16) {
                i2 += iValueAt;
            }
        }
        return new com.google.firebase.perf.util.d(new com.google.firebase.perf.metrics.c(i, i2, i3));
    }

    public final void b() {
        boolean z = this.d;
        Activity activity = this.a;
        if (z) {
            e.b("FrameMetricsAggregator is already recording %s", activity.getClass().getSimpleName());
            return;
        }
        k kVar = (k) this.b.b;
        kVar.getClass();
        if (k.g == null) {
            HandlerThread handlerThread = new HandlerThread("FrameMetricsAggregator");
            k.g = handlerThread;
            handlerThread.start();
            k.h = new Handler(k.g.getLooper());
        }
        for (int i = 0; i <= 8; i++) {
            SparseIntArray[] sparseIntArrayArr = (SparseIntArray[]) kVar.c;
            if (sparseIntArrayArr[i] == null) {
                if (((1 << i) & kVar.b) != 0) {
                    sparseIntArrayArr[i] = new SparseIntArray();
                }
            }
        }
        activity.getWindow().addOnFrameMetricsAvailableListener((WindowOnFrameMetricsAvailableListenerC1022i) kVar.e, k.h);
        ((ArrayList) kVar.d).add(new WeakReference(activity));
        this.d = true;
    }
}
