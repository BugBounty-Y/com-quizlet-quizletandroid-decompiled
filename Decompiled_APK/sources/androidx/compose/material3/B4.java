package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class B4 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ D4 a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ androidx.compose.foundation.interaction.k d;
    public final /* synthetic */ A4 e;
    public final /* synthetic */ androidx.compose.ui.graphics.V f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B4(D4 d4, boolean z, boolean z2, androidx.compose.foundation.interaction.k kVar, A4 a4, androidx.compose.ui.graphics.V v, int i) {
        super(2);
        D4 d42 = D4.a;
        D4 d43 = D4.a;
        this.a = d4;
        this.b = z;
        this.c = z2;
        this.d = kVar;
        this.e = a4;
        this.f = v;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Number) obj2).intValue();
        int iH = C0776c.H(114822145);
        D4 d4 = D4.a;
        D4 d42 = D4.a;
        this.a.a(this.b, this.c, this.d, this.e, this.f, interfaceC0806l, iH);
        return Unit.a;
    }
}
