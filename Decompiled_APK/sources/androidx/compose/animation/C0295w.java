package androidx.compose.animation;

import androidx.compose.animation.core.E0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.animation.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0295w extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ E0 a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ a0 d;
    public final /* synthetic */ b0 e;
    public final /* synthetic */ Function2 f;
    public final /* synthetic */ kotlin.jvm.functions.c g;
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0295w(E0 e0, Function1 function1, androidx.compose.ui.q qVar, a0 a0Var, b0 b0Var, Function2 function2, kotlin.jvm.functions.c cVar, int i) {
        super(2);
        this.a = e0;
        this.b = function1;
        this.c = qVar;
        this.d = a0Var;
        this.e = b0Var;
        this.f = function2;
        this.g = cVar;
        this.h = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.h | 1);
        b0 b0Var = this.e;
        Function2 function2 = this.f;
        E.c(this.a, this.b, this.c, this.d, b0Var, function2, this.g, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
