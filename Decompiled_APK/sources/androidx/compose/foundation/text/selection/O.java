package androidx.compose.foundation.text.selection;

import androidx.compose.animation.core.C0253l0;
import androidx.compose.animation.core.C0262q;
import androidx.compose.animation.core.L0;
import androidx.compose.animation.core.M0;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;

/* loaded from: classes.dex */
public abstract class O {
    public static final C0262q a = new C0262q(Float.NaN, Float.NaN);
    public static final L0 b;
    public static final long c;
    public static final C0253l0 d;

    static {
        K k = K.b;
        K k2 = K.c;
        L0 l0 = M0.a;
        b = new L0(k, k2);
        long jC = Q4.c(0.01f, 0.01f);
        c = jC;
        d = new C0253l0(new androidx.compose.ui.geometry.b(jC), 3);
    }
}
