package leakcanary;

import android.os.Handler;
import android.view.accessibility.AccessibilityNodeInfo;

/* loaded from: classes3.dex */
public final class a implements Runnable {
    @Override // java.lang.Runnable
    public final void run() {
        for (int i = 0; i < 50; i++) {
            AccessibilityNodeInfo.obtain();
        }
        w[] wVarArr = w.b;
        ((Handler) w.c.getValue()).postDelayed(this, 5000L);
    }
}
