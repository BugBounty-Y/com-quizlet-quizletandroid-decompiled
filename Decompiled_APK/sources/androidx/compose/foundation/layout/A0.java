package androidx.compose.foundation.layout;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class A0 implements z0 {
    public final float a;
    public final float b;
    public final float c;
    public final float d;

    public A0(float f, float f2, float f3, float f4) {
        this.a = f;
        this.b = f2;
        this.c = f3;
        this.d = f4;
        if (f < DefinitionKt.NO_Float_VALUE) {
            throw new IllegalArgumentException("Start padding must be non-negative");
        }
        if (f2 < DefinitionKt.NO_Float_VALUE) {
            throw new IllegalArgumentException("Top padding must be non-negative");
        }
        if (f3 < DefinitionKt.NO_Float_VALUE) {
            throw new IllegalArgumentException("End padding must be non-negative");
        }
        if (f4 < DefinitionKt.NO_Float_VALUE) {
            throw new IllegalArgumentException("Bottom padding must be non-negative");
        }
    }

    @Override // androidx.compose.foundation.layout.z0
    public final float a() {
        return this.d;
    }

    @Override // androidx.compose.foundation.layout.z0
    public final float b(androidx.compose.ui.unit.k kVar) {
        return kVar == androidx.compose.ui.unit.k.a ? this.a : this.c;
    }

    @Override // androidx.compose.foundation.layout.z0
    public final float c(androidx.compose.ui.unit.k kVar) {
        return kVar == androidx.compose.ui.unit.k.a ? this.c : this.a;
    }

    @Override // androidx.compose.foundation.layout.z0
    public final float d() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof A0)) {
            return false;
        }
        A0 a0 = (A0) obj;
        return androidx.compose.ui.unit.e.a(this.a, a0.a) && androidx.compose.ui.unit.e.a(this.b, a0.b) && androidx.compose.ui.unit.e.a(this.c, a0.c) && androidx.compose.ui.unit.e.a(this.d, a0.d);
    }

    public final int hashCode() {
        return Float.hashCode(this.d) + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.a) * 31, this.b, 31), this.c, 31);
    }

    public final String toString() {
        return "PaddingValues(start=" + ((Object) androidx.compose.ui.unit.e.b(this.a)) + ", top=" + ((Object) androidx.compose.ui.unit.e.b(this.b)) + ", end=" + ((Object) androidx.compose.ui.unit.e.b(this.c)) + ", bottom=" + ((Object) androidx.compose.ui.unit.e.b(this.d)) + ')';
    }
}
