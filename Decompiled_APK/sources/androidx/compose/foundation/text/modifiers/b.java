package androidx.compose.foundation.text.modifiers;

import androidx.compose.ui.text.L;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3214n5;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;

/* loaded from: classes.dex */
public final class b {
    public static b h;
    public final androidx.compose.ui.unit.k a;
    public final L b;
    public final androidx.compose.ui.unit.c c;
    public final androidx.compose.ui.text.font.i d;
    public final L e;
    public float f = Float.NaN;
    public float g = Float.NaN;

    public b(androidx.compose.ui.unit.k kVar, L l, androidx.compose.ui.unit.c cVar, androidx.compose.ui.text.font.i iVar) {
        this.a = kVar;
        this.b = l;
        this.c = cVar;
        this.d = iVar;
        this.e = AbstractC3214n5.c(l, kVar);
    }

    public final long a(int i, long j) {
        int i2;
        float f = this.g;
        float f2 = this.f;
        if (Float.isNaN(f) || Float.isNaN(f2)) {
            String str = c.a;
            long jB = L5.b(0, 0, 15);
            androidx.compose.ui.unit.c cVar = this.c;
            float fB = AbstractC3178j5.a(str, this.e, jB, cVar, this.d, null, 1, 96).b();
            float fB2 = AbstractC3178j5.a(c.b, this.e, L5.b(0, 0, 15), cVar, this.d, null, 2, 96).b() - fB;
            this.g = fB;
            this.f = fB2;
            f2 = fB2;
            f = fB;
        }
        if (i != 1) {
            int iRound = Math.round((f2 * (i - 1)) + f);
            i2 = iRound >= 0 ? iRound : 0;
            int iG = androidx.compose.ui.unit.a.g(j);
            if (i2 > iG) {
                i2 = iG;
            }
        } else {
            i2 = androidx.compose.ui.unit.a.i(j);
        }
        return L5.a(androidx.compose.ui.unit.a.j(j), androidx.compose.ui.unit.a.h(j), i2, androidx.compose.ui.unit.a.g(j));
    }
}
