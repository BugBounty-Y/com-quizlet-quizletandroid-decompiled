package androidx.compose.material3;

import androidx.compose.foundation.C0555x;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class S extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ Function0 a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ androidx.compose.ui.graphics.V d;
    public final /* synthetic */ K e;
    public final /* synthetic */ C0555x f;
    public final /* synthetic */ androidx.compose.foundation.layout.A0 g;
    public final /* synthetic */ androidx.compose.runtime.internal.d h;
    public final /* synthetic */ int i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S(Function0 function0, androidx.compose.ui.q qVar, boolean z, androidx.compose.ui.graphics.V v, K k, C0555x c0555x, androidx.compose.foundation.layout.A0 a0, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.a = function0;
        this.b = qVar;
        this.c = z;
        this.d = v;
        this.e = k;
        this.f = c0555x;
        this.g = a0;
        this.h = dVar;
        this.i = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.i | 1);
        androidx.compose.runtime.internal.d dVar = this.h;
        K k = this.e;
        C0555x c0555x = this.f;
        androidx.compose.foundation.layout.A0 a0 = this.g;
        Z1.j(this.a, this.b, this.c, this.d, k, c0555x, a0, dVar, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
