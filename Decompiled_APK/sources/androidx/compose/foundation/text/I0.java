package androidx.compose.foundation.text;

import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import com.google.android.gms.internal.mlkit_vision_barcode.K4;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class I0 {
    public static final com.quizlet.data.repository.explanations.myexplanations.a f = K4.b(H0.a, C0491h.o);
    public final androidx.compose.runtime.F0 a;
    public final androidx.compose.runtime.F0 b = C0776c.v(DefinitionKt.NO_Float_VALUE);
    public androidx.compose.ui.geometry.c c = androidx.compose.ui.geometry.c.e;
    public long d = androidx.compose.ui.text.K.b;
    public final InterfaceC0773a0 e;

    public I0(EnumC0320d0 enumC0320d0, float f2) {
        this.a = C0776c.v(f2);
        this.e = C0776c.y(enumC0320d0, androidx.compose.runtime.V.f);
    }

    public final float a() {
        return this.a.i();
    }

    public final void b(EnumC0320d0 enumC0320d0, androidx.compose.ui.geometry.c cVar, int i, int i2) {
        float f2 = i2 - i;
        this.b.j(f2);
        androidx.compose.ui.geometry.c cVar2 = this.c;
        float f3 = cVar2.a;
        float f4 = cVar.a;
        androidx.compose.runtime.F0 f0 = this.a;
        float f5 = cVar.b;
        if (f4 != f3 || f5 != cVar2.b) {
            boolean z = enumC0320d0 == EnumC0320d0.a;
            if (z) {
                f4 = f5;
            }
            float f6 = z ? cVar.d : cVar.c;
            float fA = a();
            float f7 = i;
            float f8 = fA + f7;
            f0.j(a() + ((f6 <= f8 && (f4 >= fA || f6 - f4 <= f7)) ? (f4 >= fA || f6 - f4 > f7) ? 0.0f : f4 - fA : f6 - f8));
            this.c = cVar;
        }
        f0.j(kotlin.ranges.l.b(a(), DefinitionKt.NO_Float_VALUE, f2));
    }
}
