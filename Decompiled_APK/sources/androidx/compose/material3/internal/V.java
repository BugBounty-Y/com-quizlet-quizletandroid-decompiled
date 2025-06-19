package androidx.compose.material3.internal;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class V extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ long b;
    public final /* synthetic */ int c;
    public final /* synthetic */ InterfaceC4938g d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public V(long j, Function2 function2, int i) {
        super(2);
        this.b = j;
        this.d = function2;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Number) obj2).intValue();
        switch (i) {
            case 0:
                Y.c(this.b, (Function2) this.d, interfaceC0806l, C0776c.H(this.c | 1));
                break;
            default:
                androidx.compose.material3.pulltorefresh.g.b((Function0) this.d, this.b, interfaceC0806l, C0776c.H(this.c | 1));
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public V(Function0 function0, long j, int i) {
        super(2);
        this.d = function0;
        this.b = j;
        this.c = i;
    }
}
