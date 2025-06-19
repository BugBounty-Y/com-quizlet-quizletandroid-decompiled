package androidx.compose.foundation.gestures;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0274x;
import androidx.compose.animation.core.InterfaceC0256n;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.compose.foundation.gestures.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0323f implements InterfaceC0319d {
    public final androidx.compose.animation.core.K0 b = AbstractC0240f.r(125, 0, new C0274x(0.25f, 0.1f, 0.25f, 1.0f), 2);

    @Override // androidx.compose.foundation.gestures.InterfaceC0319d
    public final float a(float f, float f2, float f3) {
        float fAbs = Math.abs((f2 + f) - f);
        boolean z = fAbs <= f3;
        float f4 = (0.3f * f3) - (DefinitionKt.NO_Float_VALUE * fAbs);
        float f5 = f3 - f4;
        if (z && f5 < fAbs) {
            f4 = f3 - fAbs;
        }
        return f - f4;
    }

    @Override // androidx.compose.foundation.gestures.InterfaceC0319d
    public final InterfaceC0256n b() {
        return this.b;
    }
}
