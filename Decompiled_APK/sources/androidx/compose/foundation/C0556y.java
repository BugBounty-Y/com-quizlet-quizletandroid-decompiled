package androidx.compose.foundation;

import androidx.compose.material3.Z0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0556y extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Function1 d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0556y(int i, int i2, androidx.compose.ui.q qVar, Function1 function1) {
        super(2);
        this.b = qVar;
        this.c = i;
        this.d = function1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Number) obj2).intValue();
        switch (i) {
            case 0:
                AbstractC0460p.b(this.b, this.d, interfaceC0806l, C0776c.H(this.c | 1));
                break;
            default:
                int iH = C0776c.H(7);
                Function1 function1 = this.d;
                Z0.e(this.c, iH, interfaceC0806l, this.b, function1);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0556y(androidx.compose.ui.q qVar, Function1 function1, int i) {
        super(2);
        this.b = qVar;
        this.d = function1;
        this.c = i;
    }
}
