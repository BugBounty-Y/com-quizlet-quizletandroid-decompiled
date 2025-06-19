package androidx.compose.ui.text.style;

import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class g {
    public static final g c = new g(f.b, 17);
    public final float a;
    public final int b;

    public g(float f, int i) {
        this.a = f;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        float f = gVar.a;
        float f2 = f.a;
        return Float.compare(this.a, f) == 0 && this.b == gVar.b;
    }

    public final int hashCode() {
        float f = f.a;
        return Integer.hashCode(this.b) + (Float.hashCode(this.a) * 31);
    }

    public final String toString() {
        String str;
        StringBuilder sb = new StringBuilder("LineHeightStyle(alignment=");
        float f = this.a;
        if (f == DefinitionKt.NO_Float_VALUE) {
            float f2 = f.a;
            str = "LineHeightStyle.Alignment.Top";
        } else if (f == f.a) {
            str = "LineHeightStyle.Alignment.Center";
        } else if (f == f.b) {
            str = "LineHeightStyle.Alignment.Proportional";
        } else if (f == f.c) {
            str = "LineHeightStyle.Alignment.Bottom";
        } else {
            str = "LineHeightStyle.Alignment(topPercentage = " + f + ')';
        }
        sb.append((Object) str);
        sb.append(", trim=");
        int i = this.b;
        sb.append((Object) (i == 1 ? "LineHeightStyle.Trim.FirstLineTop" : i == 16 ? "LineHeightStyle.Trim.LastLineBottom" : i == 17 ? "LineHeightStyle.Trim.Both" : i == 0 ? "LineHeightStyle.Trim.None" : "Invalid"));
        sb.append(')');
        return sb.toString();
    }
}
