package androidx.compose.ui.text.style;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class o {
    public static final o c = new o(1.0f, DefinitionKt.NO_Float_VALUE);
    public final float a;
    public final float b;

    public o(float f, float f2) {
        this.a = f;
        this.b = f2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return this.a == oVar.a && this.b == oVar.b;
    }

    public final int hashCode() {
        return Float.hashCode(this.b) + (Float.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TextGeometricTransform(scaleX=");
        sb.append(this.a);
        sb.append(", skewX=");
        return android.support.v4.media.session.a.p(sb, this.b, ')');
    }
}
