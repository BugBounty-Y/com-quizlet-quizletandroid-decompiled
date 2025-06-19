package androidx.compose.animation;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.K0;
import androidx.compose.animation.core.V0;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;

/* loaded from: classes.dex */
public abstract class H {
    public static final long a = R5.a(Integer.MIN_VALUE, Integer.MIN_VALUE);

    public static androidx.compose.ui.q a(androidx.compose.ui.q qVar, K0 k0, int i) {
        androidx.compose.animation.core.D dQ = k0;
        if ((i & 1) != 0) {
            Object obj = V0.a;
            dQ = AbstractC0240f.q(1, new androidx.compose.ui.unit.j(R5.a(1, 1)));
        }
        return androidx.compose.ui.draw.g.d(qVar).g(new SizeAnimationModifierElement(dQ));
    }
}
