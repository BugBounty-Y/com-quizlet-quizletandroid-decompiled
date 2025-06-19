package androidx.compose.foundation;

import android.content.Context;
import android.widget.EdgeEffect;
import com.google.android.gms.internal.mlkit_vision_barcode.K5;
import com.skydoves.balloon.internals.DefinitionKt;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.foundation.a0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0300a0 extends EdgeEffect {
    public final float a;
    public float b;

    public C0300a0(@NotNull Context context) {
        super(context);
        this.a = K5.b(context).a * 1;
    }

    @Override // android.widget.EdgeEffect
    public final void onAbsorb(int i) {
        this.b = DefinitionKt.NO_Float_VALUE;
        super.onAbsorb(i);
    }

    @Override // android.widget.EdgeEffect
    public final void onPull(float f, float f2) {
        this.b = DefinitionKt.NO_Float_VALUE;
        super.onPull(f, f2);
    }

    @Override // android.widget.EdgeEffect
    public final void onRelease() {
        this.b = DefinitionKt.NO_Float_VALUE;
        super.onRelease();
    }

    @Override // android.widget.EdgeEffect
    public final void onPull(float f) {
        this.b = DefinitionKt.NO_Float_VALUE;
        super.onPull(f);
    }
}
