package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class X4 {
    public static final com.quizlet.data.repository.explanations.myexplanations.a d = com.google.android.gms.internal.mlkit_vision_barcode.K4.b(M4.d, C0736u.x);
    public final androidx.compose.runtime.F0 a;
    public final androidx.compose.runtime.F0 b;
    public final androidx.compose.runtime.F0 c;

    public X4(float f, float f2, float f3) {
        this.a = C0776c.v(f);
        this.b = C0776c.v(f3);
        this.c = C0776c.v(f2);
    }

    public final float a() {
        return c() == DefinitionKt.NO_Float_VALUE ? DefinitionKt.NO_Float_VALUE : b() / c();
    }

    public final float b() {
        return this.c.i();
    }

    public final float c() {
        return this.a.i();
    }

    public final void d(float f) {
        this.c.j(kotlin.ranges.l.b(f, c(), DefinitionKt.NO_Float_VALUE));
    }
}
