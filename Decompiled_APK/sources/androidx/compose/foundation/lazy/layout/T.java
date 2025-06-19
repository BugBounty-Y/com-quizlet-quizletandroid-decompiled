package androidx.compose.foundation.lazy.layout;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class T extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ kotlin.reflect.k a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ c0 c;
    public final /* synthetic */ Function2 d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public T(kotlin.reflect.k kVar, androidx.compose.ui.q qVar, c0 c0Var, Function2 function2, int i) {
        super(2);
        this.a = kVar;
        this.b = qVar;
        this.c = c0Var;
        this.d = function2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(1);
        AbstractC0448u.a(this.a, this.b, this.c, this.d, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
