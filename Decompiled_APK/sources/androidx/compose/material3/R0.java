package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class R0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ String f;
    public final /* synthetic */ C0699p0 g;
    public final /* synthetic */ androidx.compose.runtime.internal.d h;
    public final /* synthetic */ int i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public R0(androidx.compose.ui.q qVar, boolean z, boolean z2, Function0 function0, boolean z3, String str, C0699p0 c0699p0, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.a = qVar;
        this.b = z;
        this.c = z2;
        this.d = function0;
        this.e = z3;
        this.f = str;
        this.g = c0699p0;
        this.h = dVar;
        this.i = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.i | 1);
        C0699p0 c0699p0 = this.g;
        androidx.compose.runtime.internal.d dVar = this.h;
        String str = this.f;
        Z0.l(this.a, this.b, this.c, this.d, this.e, str, c0699p0, dVar, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
