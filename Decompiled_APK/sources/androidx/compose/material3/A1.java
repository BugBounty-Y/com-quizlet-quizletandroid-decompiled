package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class A1 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ Function0 a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ C0768z1 d;
    public final /* synthetic */ Function2 e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A1(Function0 function0, androidx.compose.ui.q qVar, boolean z, C0768z1 c0768z1, Function2 function2, int i, int i2) {
        super(2);
        this.a = function0;
        this.b = qVar;
        this.c = z;
        this.d = c0768z1;
        this.e = function2;
        this.f = i;
        this.g = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.f | 1);
        C0768z1 c0768z1 = this.d;
        Z1.h(this.a, this.b, this.c, c0768z1, this.e, (InterfaceC0806l) obj, iH, this.g);
        return Unit.a;
    }
}
