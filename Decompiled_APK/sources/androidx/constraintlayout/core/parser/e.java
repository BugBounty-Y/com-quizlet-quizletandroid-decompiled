package androidx.constraintlayout.core.parser;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class e extends c {
    public float e;

    public e(float f) {
        super(null);
        this.e = f;
    }

    @Override // androidx.constraintlayout.core.parser.c
    public final float e() {
        char[] cArr;
        if (Float.isNaN(this.e) && (cArr = this.a) != null && cArr.length >= 1) {
            this.e = Float.parseFloat(c());
        }
        return this.e;
    }

    @Override // androidx.constraintlayout.core.parser.c
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof e) {
            float fE = e();
            float fE2 = ((e) obj).e();
            if ((Float.isNaN(fE) && Float.isNaN(fE2)) || fE == fE2) {
                return true;
            }
        }
        return false;
    }

    @Override // androidx.constraintlayout.core.parser.c
    public final int g() {
        char[] cArr;
        if (Float.isNaN(this.e) && (cArr = this.a) != null && cArr.length >= 1) {
            this.e = Integer.parseInt(c());
        }
        return (int) this.e;
    }

    @Override // androidx.constraintlayout.core.parser.c
    public final int hashCode() {
        int iHashCode = super.hashCode() * 31;
        float f = this.e;
        return iHashCode + (f != DefinitionKt.NO_Float_VALUE ? Float.floatToIntBits(f) : 0);
    }
}
