package androidx.compose.ui.window;

import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;

/* loaded from: classes.dex */
public final class a implements x {
    public final long a;

    public a(long j) {
        this.a = j;
    }

    @Override // androidx.compose.ui.window.x
    public final long a(androidx.compose.ui.unit.i iVar, long j, androidx.compose.ui.unit.k kVar, long j2) {
        long jA = R5.a(iVar.b(), iVar.a());
        androidx.compose.ui.i iVar2 = androidx.compose.ui.b.a;
        long jA2 = iVar2.a(0L, jA, kVar);
        long jA3 = iVar2.a(0L, j2, kVar);
        long j3 = ((-((int) (jA3 & 4294967295L))) & 4294967295L) | ((-((int) (jA3 >> 32))) << 32);
        long j4 = this.a;
        return androidx.compose.ui.unit.h.d(androidx.compose.ui.unit.h.d(androidx.compose.ui.unit.h.d(P5.b(iVar.a, iVar.b), jA2), j3), P5.b(((int) (j4 >> 32)) * (kVar == androidx.compose.ui.unit.k.a ? 1 : -1), (int) (j4 & 4294967295L)));
    }
}
