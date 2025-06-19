package androidx.activity.compose;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class h extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ int c;
    public final /* synthetic */ int d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(int i, int i2, Function0 function0, boolean z) {
        super(2);
        this.a = z;
        this.b = function0;
        this.c = i;
        this.d = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.c | 1);
        Function0 function0 = this.b;
        int i = this.d;
        androidx.work.impl.t.a(this.a, function0, (InterfaceC0806l) obj, iH, i);
        return Unit.a;
    }
}
