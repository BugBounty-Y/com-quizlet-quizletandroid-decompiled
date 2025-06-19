package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0680m extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.runtime.internal.d a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ androidx.compose.ui.n c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ T1 e;
    public final /* synthetic */ androidx.compose.foundation.layout.A0 f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0680m(androidx.compose.runtime.internal.d dVar, Function0 function0, androidx.compose.ui.n nVar, boolean z, T1 t1, androidx.compose.foundation.layout.A0 a0, int i) {
        super(2);
        this.a = dVar;
        this.b = function0;
        this.c = nVar;
        this.d = z;
        this.e = t1;
        this.f = a0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(7);
        androidx.compose.runtime.internal.d dVar = this.a;
        boolean z = this.d;
        T1 t1 = this.e;
        AbstractC0686n.b(dVar, this.b, this.c, z, t1, this.f, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
