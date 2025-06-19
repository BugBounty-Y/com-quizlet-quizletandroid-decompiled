package androidx.compose.animation.core;

import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: androidx.compose.animation.core.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0265s extends AbstractC0267t {
    public float a;
    public float b;
    public float c;
    public float d;

    public C0265s(float f, float f2, float f3, float f4) {
        this.a = f;
        this.b = f2;
        this.c = f3;
        this.d = f4;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final float a(int i) {
        return i != 0 ? i != 1 ? i != 2 ? i != 3 ? DefinitionKt.NO_Float_VALUE : this.d : this.c : this.b : this.a;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final int b() {
        return 4;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final AbstractC0267t c() {
        return new C0265s(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final void d() {
        this.a = DefinitionKt.NO_Float_VALUE;
        this.b = DefinitionKt.NO_Float_VALUE;
        this.c = DefinitionKt.NO_Float_VALUE;
        this.d = DefinitionKt.NO_Float_VALUE;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final void e(float f, int i) {
        if (i == 0) {
            this.a = f;
            return;
        }
        if (i == 1) {
            this.b = f;
        } else if (i == 2) {
            this.c = f;
        } else {
            if (i != 3) {
                return;
            }
            this.d = f;
        }
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C0265s)) {
            return false;
        }
        C0265s c0265s = (C0265s) obj;
        return c0265s.a == this.a && c0265s.b == this.b && c0265s.c == this.c && c0265s.d == this.d;
    }

    public final int hashCode() {
        return Float.hashCode(this.d) + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.a) * 31, this.b, 31), this.c, 31);
    }

    public final String toString() {
        return "AnimationVector4D: v1 = " + this.a + ", v2 = " + this.b + ", v3 = " + this.c + ", v4 = " + this.d;
    }
}
