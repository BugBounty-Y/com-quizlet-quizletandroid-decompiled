package androidx.compose.material3.internal;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class N extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ androidx.compose.ui.text.L c;
    public final /* synthetic */ Function2 d;
    public final /* synthetic */ int e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ N(long j, androidx.compose.ui.text.L l, Function2 function2, int i, int i2) {
        super(2);
        this.a = i2;
        this.b = j;
        this.c = l;
        this.d = function2;
        this.e = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.e | 1);
                androidx.compose.ui.text.L l = this.c;
                Function2 function2 = this.d;
                AbstractC0646j.a(this.b, l, function2, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.e | 1);
                androidx.compose.ui.text.L l2 = this.c;
                Function2 function22 = this.d;
                Y.b(this.b, l2, function22, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}
