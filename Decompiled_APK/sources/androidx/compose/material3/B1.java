package androidx.compose.material3;

import androidx.compose.foundation.C0555x;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class B1 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ androidx.compose.ui.graphics.V e;
    public final /* synthetic */ E1 f;
    public final /* synthetic */ C0555x g;
    public final /* synthetic */ androidx.compose.runtime.internal.d h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B1(boolean z, Function1 function1, androidx.compose.ui.q qVar, boolean z2, androidx.compose.ui.graphics.V v, E1 e1, C0555x c0555x, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.a = z;
        this.b = function1;
        this.c = qVar;
        this.d = z2;
        this.e = v;
        this.f = e1;
        this.g = c0555x;
        this.h = dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(100663297);
        androidx.compose.runtime.internal.d dVar = this.h;
        E1 e1 = this.f;
        C0555x c0555x = this.g;
        Z1.k(this.a, this.b, this.c, this.d, this.e, e1, c0555x, dVar, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
