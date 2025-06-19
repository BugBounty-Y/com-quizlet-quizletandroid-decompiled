package androidx.compose.foundation.text;

import androidx.compose.runtime.C0776c;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class G0 implements androidx.compose.foundation.gestures.E0 {
    public final /* synthetic */ androidx.compose.foundation.gestures.E0 a;
    public final androidx.compose.runtime.E b;
    public final androidx.compose.runtime.E c;

    public G0(androidx.compose.foundation.gestures.E0 e0, I0 i0) {
        this.a = e0;
        this.b = C0776c.q(new F0(i0, 1));
        this.c = C0776c.q(new F0(i0, 0));
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean a() {
        return this.a.a();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean b() {
        return ((Boolean) this.c.getValue()).booleanValue();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final Object c(androidx.compose.foundation.u0 u0Var, Function2 function2, kotlin.coroutines.jvm.internal.c cVar) {
        return this.a.c(u0Var, function2, cVar);
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final boolean d() {
        return ((Boolean) this.b.getValue()).booleanValue();
    }

    @Override // androidx.compose.foundation.gestures.E0
    public final float e(float f) {
        return this.a.e(f);
    }
}
