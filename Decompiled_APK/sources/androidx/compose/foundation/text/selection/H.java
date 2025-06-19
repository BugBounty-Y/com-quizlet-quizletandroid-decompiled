package androidx.compose.foundation.text.selection;

import com.google.android.gms.internal.mlkit_vision_barcode.Q4;

/* loaded from: classes.dex */
public abstract class H {
    public static final float a;
    public static final float b;
    public static final androidx.compose.ui.semantics.u c = new androidx.compose.ui.semantics.u("SelectionHandleInfo");

    static {
        float f = 25;
        a = f;
        b = f;
    }

    public static final long a(long j) {
        return Q4.c(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j) - 1.0f);
    }
}
