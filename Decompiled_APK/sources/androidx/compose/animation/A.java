package androidx.compose.animation;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class A extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ kotlin.jvm.functions.c i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public A(androidx.compose.foundation.contextmenu.o oVar, Function0 function0, Function1 function1, androidx.compose.ui.n nVar, boolean z, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        super(2);
        this.a = 2;
        this.h = oVar;
        this.c = function0;
        this.d = (kotlin.jvm.internal.r) function1;
        this.e = nVar;
        this.b = z;
        this.i = dVar;
        this.f = i;
        this.g = i2;
    }

    /* JADX WARN: Type inference failed for: r3v5, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.f | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.i;
                a0 a0Var = (a0) this.c;
                b0 b0Var = (b0) this.d;
                E.g(this.b, (androidx.compose.ui.q) this.h, a0Var, b0Var, (String) this.e, dVar, (InterfaceC0806l) obj, iH, this.g);
                break;
            case 1:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.f | 1);
                b0 b0Var2 = (b0) this.d;
                E.f(this.b, (androidx.compose.ui.n) this.h, (a0) this.c, b0Var2, (String) this.e, this.i, (InterfaceC0806l) obj, iH2, this.g);
                break;
            default:
                ((Number) obj2).intValue();
                int iH3 = C0776c.H(this.f | 1);
                androidx.compose.runtime.internal.d dVar2 = (androidx.compose.runtime.internal.d) this.i;
                ?? r3 = (kotlin.jvm.internal.r) this.d;
                androidx.compose.ui.n nVar = (androidx.compose.ui.n) this.e;
                com.google.android.gms.internal.mlkit_vision_barcode.V.b((androidx.compose.foundation.contextmenu.o) this.h, (Function0) this.c, r3, nVar, this.b, dVar2, (InterfaceC0806l) obj, iH3, this.g);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ A(boolean z, androidx.compose.ui.q qVar, a0 a0Var, b0 b0Var, String str, kotlin.jvm.functions.c cVar, int i, int i2, int i3) {
        super(2);
        this.a = i3;
        this.b = z;
        this.h = qVar;
        this.c = a0Var;
        this.d = b0Var;
        this.e = str;
        this.i = cVar;
        this.f = i;
        this.g = i2;
    }
}
