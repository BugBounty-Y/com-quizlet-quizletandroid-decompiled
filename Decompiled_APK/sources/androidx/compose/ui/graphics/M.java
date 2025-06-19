package androidx.compose.ui.graphics;

import com.google.android.gms.internal.mlkit_vision_barcode.S4;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class M extends N {
    public final androidx.compose.ui.geometry.d a;
    public final C0850j b;

    public M(androidx.compose.ui.geometry.d dVar) {
        C0850j c0850jH;
        this.a = dVar;
        if (S4.g(dVar)) {
            c0850jH = null;
        } else {
            c0850jH = F.h();
            O.b(c0850jH, dVar);
        }
        this.b = c0850jH;
    }

    @Override // androidx.compose.ui.graphics.N
    public final androidx.compose.ui.geometry.c a() {
        androidx.compose.ui.geometry.d dVar = this.a;
        return new androidx.compose.ui.geometry.c(dVar.a, dVar.b, dVar.c, dVar.d);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof M) {
            return Intrinsics.b(this.a, ((M) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
