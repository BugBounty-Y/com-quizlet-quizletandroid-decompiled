package androidx.core.app;

import android.util.SparseIntArray;
import android.view.FrameMetrics;
import android.view.Window;

/* renamed from: androidx.core.app.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class WindowOnFrameMetricsAvailableListenerC1022i implements Window.OnFrameMetricsAvailableListener {
    public final /* synthetic */ com.google.android.gms.cloudmessaging.k a;

    public WindowOnFrameMetricsAvailableListenerC1022i(com.google.android.gms.cloudmessaging.k kVar) {
        this.a = kVar;
    }

    @Override // android.view.Window.OnFrameMetricsAvailableListener
    public final void onFrameMetricsAvailable(Window window, FrameMetrics frameMetrics, int i) {
        com.google.android.gms.cloudmessaging.k kVar = this.a;
        if ((kVar.b & 1) != 0) {
            SparseIntArray sparseIntArray = ((SparseIntArray[]) kVar.c)[0];
            long metric = frameMetrics.getMetric(8);
            if (sparseIntArray != null) {
                int i2 = (int) ((500000 + metric) / 1000000);
                if (metric >= 0) {
                    sparseIntArray.put(i2, sparseIntArray.get(i2) + 1);
                }
            }
        }
    }
}
