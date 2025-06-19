package androidx.constraintlayout.motion.utils;

import android.view.View;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3125d6;

/* loaded from: classes.dex */
public final class c extends f {
    public float[] g;

    @Override // androidx.constraintlayout.motion.utils.f
    public final void b(View view, float f) {
        float fA = a(f);
        float[] fArr = this.g;
        fArr[0] = fA;
        AbstractC3125d6.c(null, view, fArr);
    }
}
