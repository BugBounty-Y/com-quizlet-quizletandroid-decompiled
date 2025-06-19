package androidx.compose.foundation.gestures;

import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.compose.foundation.gestures.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0348s implements InterfaceC0334k0 {
    public final /* synthetic */ C0350t a;

    public C0348s(C0350t c0350t) {
        this.a = c0350t;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // androidx.compose.foundation.gestures.InterfaceC0334k0
    public final float a(float f) {
        if (Float.isNaN(f)) {
            return DefinitionKt.NO_Float_VALUE;
        }
        C0350t c0350t = this.a;
        float fFloatValue = ((Number) c0350t.a.invoke(Float.valueOf(f))).floatValue();
        ((androidx.compose.runtime.L0) c0350t.e).setValue(Boolean.valueOf(fFloatValue > DefinitionKt.NO_Float_VALUE));
        ((androidx.compose.runtime.L0) c0350t.f).setValue(Boolean.valueOf(fFloatValue < DefinitionKt.NO_Float_VALUE));
        return fFloatValue;
    }
}
