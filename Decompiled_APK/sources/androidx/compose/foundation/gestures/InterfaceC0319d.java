package androidx.compose.foundation.gestures;

import androidx.compose.animation.core.InterfaceC0256n;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.compose.foundation.gestures.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public interface InterfaceC0319d {
    public static final C0317c a = C0317c.a;

    default float a(float f, float f2, float f3) {
        a.getClass();
        float f4 = f2 + f;
        if ((f >= DefinitionKt.NO_Float_VALUE && f4 <= f3) || (f < DefinitionKt.NO_Float_VALUE && f4 > f3)) {
            return DefinitionKt.NO_Float_VALUE;
        }
        float f5 = f4 - f3;
        return Math.abs(f) < Math.abs(f5) ? f : f5;
    }

    default InterfaceC0256n b() {
        a.getClass();
        return C0317c.b;
    }
}
