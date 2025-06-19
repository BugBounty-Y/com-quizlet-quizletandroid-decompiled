package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class T extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ Function0 a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ androidx.compose.ui.graphics.V d;
    public final /* synthetic */ K e;
    public final /* synthetic */ androidx.compose.foundation.layout.A0 f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ int h;
    public final /* synthetic */ int i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public T(Function0 function0, androidx.compose.ui.q qVar, boolean z, androidx.compose.ui.graphics.V v, K k, androidx.compose.foundation.layout.A0 a0, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        super(2);
        this.a = function0;
        this.b = qVar;
        this.c = z;
        this.d = v;
        this.e = k;
        this.f = a0;
        this.g = dVar;
        this.h = i;
        this.i = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.h | 1);
        androidx.compose.runtime.internal.d dVar = this.g;
        androidx.compose.foundation.layout.A0 a0 = this.f;
        Z1.m(this.a, this.b, this.c, this.d, this.e, a0, dVar, (InterfaceC0806l) obj, iH, this.i);
        return Unit.a;
    }
}
