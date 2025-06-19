package androidx.compose.animation.core;

import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.compose.animation.core.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0262q extends AbstractC0267t {
    public float a;
    public float b;

    public C0262q(float f, float f2) {
        this.a = f;
        this.b = f2;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final float a(int i) {
        return i != 0 ? i != 1 ? DefinitionKt.NO_Float_VALUE : this.b : this.a;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final int b() {
        return 2;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final AbstractC0267t c() {
        return new C0262q(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final void d() {
        this.a = DefinitionKt.NO_Float_VALUE;
        this.b = DefinitionKt.NO_Float_VALUE;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final void e(float f, int i) {
        if (i == 0) {
            this.a = f;
        } else {
            if (i != 1) {
                return;
            }
            this.b = f;
        }
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C0262q)) {
            return false;
        }
        C0262q c0262q = (C0262q) obj;
        return c0262q.a == this.a && c0262q.b == this.b;
    }

    public final int hashCode() {
        return Float.hashCode(this.b) + (Float.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "AnimationVector2D: v1 = " + this.a + ", v2 = " + this.b;
    }
}
