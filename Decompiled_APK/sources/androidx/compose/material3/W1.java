package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class W1 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Function0 d;
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public W1(androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, boolean z, Function0 function0, int i) {
        super(2);
        this.b = dVar;
        this.f = dVar2;
        this.g = dVar3;
        this.h = dVar4;
        this.c = z;
        this.d = function0;
        this.e = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.e | 1);
                androidx.compose.runtime.internal.d dVar = this.b;
                boolean z = this.c;
                T1 t1 = (T1) this.g;
                X1.b(dVar, this.d, (androidx.compose.ui.n) this.f, z, t1, (androidx.compose.foundation.layout.A0) this.h, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Number) obj2).intValue();
                M2.c(this.b, (androidx.compose.runtime.internal.d) this.f, (androidx.compose.runtime.internal.d) this.g, (androidx.compose.runtime.internal.d) this.h, this.c, this.d, (InterfaceC0806l) obj, C0776c.H(this.e | 1));
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public W1(androidx.compose.runtime.internal.d dVar, Function0 function0, androidx.compose.ui.n nVar, boolean z, T1 t1, androidx.compose.foundation.layout.A0 a0, int i) {
        super(2);
        this.b = dVar;
        this.d = function0;
        this.f = nVar;
        this.c = z;
        this.g = t1;
        this.h = a0;
        this.e = i;
    }
}
