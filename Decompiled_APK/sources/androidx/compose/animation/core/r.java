package androidx.compose.animation.core;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class r extends AbstractC0267t {
    public float a;
    public float b;
    public float c;

    public r(float f, float f2, float f3) {
        this.a = f;
        this.b = f2;
        this.c = f3;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final float a(int i) {
        return i != 0 ? i != 1 ? i != 2 ? DefinitionKt.NO_Float_VALUE : this.c : this.b : this.a;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final int b() {
        return 3;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final AbstractC0267t c() {
        return new r(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final void d() {
        this.a = DefinitionKt.NO_Float_VALUE;
        this.b = DefinitionKt.NO_Float_VALUE;
        this.c = DefinitionKt.NO_Float_VALUE;
    }

    @Override // androidx.compose.animation.core.AbstractC0267t
    public final void e(float f, int i) {
        if (i == 0) {
            this.a = f;
        } else if (i == 1) {
            this.b = f;
        } else {
            if (i != 2) {
                return;
            }
            this.c = f;
        }
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof r)) {
            return false;
        }
        r rVar = (r) obj;
        return rVar.a == this.a && rVar.b == this.b && rVar.c == this.c;
    }

    public final int hashCode() {
        return Float.hashCode(this.c) + android.support.v4.media.session.a.b(Float.hashCode(this.a) * 31, this.b, 31);
    }

    public final String toString() {
        return "AnimationVector3D: v1 = " + this.a + ", v2 = " + this.b + ", v3 = " + this.c;
    }
}
