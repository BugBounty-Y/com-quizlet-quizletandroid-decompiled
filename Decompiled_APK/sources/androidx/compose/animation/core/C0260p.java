package androidx.compose.animation.core;

import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.compose.animation.core.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0260p extends AbstractC0267t {
    public float a;

    public C0260p(float f) {
        this.a = f;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final float a(int i) {
        return i == 0 ? this.a : DefinitionKt.NO_Float_VALUE;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final int b() {
        return 1;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final AbstractC0267t c() {
        return new C0260p(DefinitionKt.NO_Float_VALUE);
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final void d() {
        this.a = DefinitionKt.NO_Float_VALUE;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final void e(float f, int i) {
        if (i == 0) {
            this.a = f;
        }
    }

    public final boolean equals(Object obj) {
        return (obj instanceof C0260p) && ((C0260p) obj).a == this.a;
    }

    public final int hashCode() {
        return Float.hashCode(this.a);
    }

    public final String toString() {
        return "AnimationVector1D: value = " + this.a;
    }
}
