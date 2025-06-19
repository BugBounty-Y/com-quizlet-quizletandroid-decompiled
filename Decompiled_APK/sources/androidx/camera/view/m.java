package androidx.camera.view;

import android.animation.ValueAnimator;
import androidx.camera.core.J;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class m implements J {
    public ValueAnimator a;
    public final /* synthetic */ n b;

    public m(n nVar) {
        this.b = nVar;
    }

    @Override // androidx.camera.core.J
    public final void clear() {
        AbstractC3053s1.f(3, "ScreenFlashView");
        ValueAnimator valueAnimator = this.a;
        if (valueAnimator != null) {
            valueAnimator.cancel();
            this.a = null;
        }
        n nVar = this.b;
        nVar.setAlpha(DefinitionKt.NO_Float_VALUE);
        nVar.setBrightness(DefinitionKt.NO_Float_VALUE);
    }
}
