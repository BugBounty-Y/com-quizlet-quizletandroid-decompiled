package androidx.compose.ui.window;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class k extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ x a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ y c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(x xVar, Function0 function0, y yVar, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        super(2);
        this.a = xVar;
        this.b = function0;
        this.c = yVar;
        this.d = dVar;
        this.e = i;
        this.f = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.e | 1);
        androidx.compose.runtime.internal.d dVar = this.d;
        Function0 function0 = this.b;
        l.a(this.a, function0, this.c, dVar, (InterfaceC0806l) obj, iH, this.f);
        return Unit.a;
    }
}
