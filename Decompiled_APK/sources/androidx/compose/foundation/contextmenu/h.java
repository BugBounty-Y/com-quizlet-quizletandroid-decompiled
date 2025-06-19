package androidx.compose.foundation.contextmenu;

import androidx.compose.ui.window.x;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.Z;

/* loaded from: classes.dex */
public final class h implements x {
    public final long a;

    public h(long j) {
        this.a = j;
    }

    @Override // androidx.compose.ui.window.x
    public final long a(androidx.compose.ui.unit.i iVar, long j, androidx.compose.ui.unit.k kVar, long j2) {
        int i = iVar.a;
        long j3 = this.a;
        return P5.b(Z.a(kVar == androidx.compose.ui.unit.k.a, i + ((int) (j3 >> 32)), (int) (j2 >> 32), (int) (j >> 32)), Z.a(true, iVar.b + ((int) (j3 & 4294967295L)), (int) (j2 & 4294967295L), (int) (j & 4294967295L)));
    }
}
