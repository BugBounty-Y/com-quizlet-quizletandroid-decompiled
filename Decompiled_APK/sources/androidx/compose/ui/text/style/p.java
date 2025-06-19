package androidx.compose.ui.text.style;

import com.google.android.gms.internal.mlkit_vision_barcode.S5;

/* loaded from: classes.dex */
public final class p {
    public static final p c = new p(S5.g(0), S5.g(0));
    public final long a;
    public final long b;

    public p(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p)) {
            return false;
        }
        p pVar = (p) obj;
        return androidx.compose.ui.unit.m.a(this.a, pVar.a) && androidx.compose.ui.unit.m.a(this.b, pVar.b);
    }

    public final int hashCode() {
        androidx.compose.ui.unit.n[] nVarArr = androidx.compose.ui.unit.m.b;
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "TextIndent(firstLine=" + ((Object) androidx.compose.ui.unit.m.d(this.a)) + ", restLine=" + ((Object) androidx.compose.ui.unit.m.d(this.b)) + ')';
    }
}
