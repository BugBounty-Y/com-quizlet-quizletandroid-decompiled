package androidx.compose.material3;

import androidx.compose.foundation.C0555x;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class Q extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ Function0 a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ androidx.compose.ui.graphics.V d;
    public final /* synthetic */ K e;
    public final /* synthetic */ P f;
    public final /* synthetic */ C0555x g;
    public final /* synthetic */ androidx.compose.foundation.layout.A0 h;
    public final /* synthetic */ androidx.compose.foundation.interaction.l i;
    public final /* synthetic */ androidx.compose.runtime.internal.d j;
    public final /* synthetic */ int k;
    public final /* synthetic */ int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Q(Function0 function0, androidx.compose.ui.q qVar, boolean z, androidx.compose.ui.graphics.V v, K k, P p, C0555x c0555x, androidx.compose.foundation.layout.A0 a0, androidx.compose.foundation.interaction.l lVar, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        super(2);
        this.a = function0;
        this.b = qVar;
        this.c = z;
        this.d = v;
        this.e = k;
        this.f = p;
        this.g = c0555x;
        this.h = a0;
        this.i = lVar;
        this.j = dVar;
        this.k = i;
        this.l = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.k | 1);
        androidx.compose.runtime.internal.d dVar = this.j;
        androidx.compose.foundation.layout.A0 a0 = this.h;
        Z1.b(this.a, this.b, this.c, this.d, this.e, this.f, this.g, a0, this.i, dVar, (InterfaceC0806l) obj, iH, this.l);
        return Unit.a;
    }
}
