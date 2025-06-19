package androidx.compose.ui.text;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;

/* loaded from: classes.dex */
public final class v {
    public final long a;
    public final long b;
    public final int c;

    public v(long j, long j2, int i) {
        this.a = j;
        this.b = j2;
        this.c = i;
        if (S5.h(j)) {
            throw new IllegalArgumentException("width cannot be TextUnit.Unspecified");
        }
        if (S5.h(j2)) {
            throw new IllegalArgumentException("height cannot be TextUnit.Unspecified");
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof v)) {
            return false;
        }
        v vVar = (v) obj;
        return androidx.compose.ui.unit.m.a(this.a, vVar.a) && androidx.compose.ui.unit.m.a(this.b, vVar.b) && this.c == vVar.c;
    }

    public final int hashCode() {
        androidx.compose.ui.unit.n[] nVarArr = androidx.compose.ui.unit.m.b;
        return Integer.hashCode(this.c) + d0.d(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Placeholder(width=");
        sb.append((Object) androidx.compose.ui.unit.m.d(this.a));
        sb.append(", height=");
        sb.append((Object) androidx.compose.ui.unit.m.d(this.b));
        sb.append(", placeholderVerticalAlign=");
        int i = this.c;
        sb.append((Object) (i == 1 ? "AboveBaseline" : i == 2 ? "Top" : i == 3 ? "Bottom" : i == 4 ? "Center" : i == 5 ? "TextTop" : i == 6 ? "TextBottom" : i == 7 ? "TextCenter" : "Invalid"));
        sb.append(')');
        return sb.toString();
    }
}
