package androidx.core.view;

import android.os.Build;
import android.view.animation.Interpolator;

/* loaded from: classes.dex */
public final class m0 {
    public l0 a;

    public m0(int i, Interpolator interpolator, long j) {
        if (Build.VERSION.SDK_INT >= 30) {
            this.a = new k0(androidx.activity.result.contract.c.i(i, interpolator, j));
        } else {
            this.a = new i0(i, interpolator, j);
        }
    }
}
