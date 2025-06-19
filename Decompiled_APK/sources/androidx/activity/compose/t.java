package androidx.activity.compose;

import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.foundation.text.selection.i0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class t extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(i0 i0Var, boolean z, int i) {
        super(2);
        this.d = i0Var;
        this.b = z;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Number) obj2).intValue();
        switch (i) {
            case 0:
                androidx.work.impl.model.f.a(this.b, (Function2) this.d, interfaceC0806l, C0776c.H(this.c | 1));
                break;
            default:
                AbstractC0484d0.j((i0) this.d, this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(boolean z, Function2 function2, int i) {
        super(2);
        this.b = z;
        this.d = function2;
        this.c = i;
    }
}
