package androidx.compose.animation;

import androidx.compose.foundation.layout.H0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class B extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ H0 a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ androidx.compose.ui.n c;
    public final /* synthetic */ a0 d;
    public final /* synthetic */ b0 e;
    public final /* synthetic */ String f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(H0 h0, boolean z, androidx.compose.ui.n nVar, a0 a0Var, b0 b0Var, String str, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.a = h0;
        this.b = z;
        this.c = nVar;
        this.d = a0Var;
        this.e = b0Var;
        this.f = str;
        this.g = dVar;
        this.h = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.h | 1);
        androidx.compose.runtime.internal.d dVar = this.g;
        a0 a0Var = this.d;
        b0 b0Var = this.e;
        E.e(this.a, this.b, this.c, a0Var, b0Var, this.f, dVar, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
