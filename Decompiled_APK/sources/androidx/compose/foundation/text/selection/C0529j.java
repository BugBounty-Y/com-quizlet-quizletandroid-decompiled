package androidx.compose.foundation.text.selection;

import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;

/* renamed from: androidx.compose.foundation.text.selection.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0529j implements androidx.compose.ui.window.x {
    public final androidx.compose.ui.d a;
    public final InterfaceC0533n b;
    public long c = 0;

    public C0529j(androidx.compose.ui.d dVar, InterfaceC0533n interfaceC0533n) {
        this.a = dVar;
        this.b = interfaceC0533n;
    }

    @Override // androidx.compose.ui.window.x
    public final long a(androidx.compose.ui.unit.i iVar, long j, androidx.compose.ui.unit.k kVar, long j2) {
        long jA = this.b.a();
        if (!Q4.h(jA)) {
            jA = this.c;
        }
        this.c = jA;
        return androidx.compose.ui.unit.h.d(androidx.compose.ui.unit.h.d(P5.b(iVar.a, iVar.b), P5.e(jA)), this.a.a(j2, 0L, kVar));
    }
}
