package androidx.compose.foundation.lazy;

import androidx.compose.foundation.gestures.InterfaceC0314a0;
import androidx.compose.foundation.layout.InterfaceC0388h;
import androidx.compose.foundation.layout.InterfaceC0394k;
import androidx.compose.foundation.layout.z0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3146g0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class k extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ A b;
    public final /* synthetic */ z0 c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ InterfaceC0314a0 e;
    public final /* synthetic */ boolean f;
    public final /* synthetic */ androidx.compose.ui.g g;
    public final /* synthetic */ InterfaceC0394k h;
    public final /* synthetic */ androidx.compose.ui.h i;
    public final /* synthetic */ InterfaceC0388h j;
    public final /* synthetic */ Function1 k;
    public final /* synthetic */ int l;
    public final /* synthetic */ int m;
    public final /* synthetic */ int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(androidx.compose.ui.q qVar, A a, z0 z0Var, boolean z, InterfaceC0314a0 interfaceC0314a0, boolean z2, androidx.compose.ui.g gVar, InterfaceC0394k interfaceC0394k, androidx.compose.ui.h hVar, InterfaceC0388h interfaceC0388h, Function1 function1, int i, int i2, int i3) {
        super(2);
        this.a = qVar;
        this.b = a;
        this.c = z0Var;
        this.d = z;
        this.e = interfaceC0314a0;
        this.f = z2;
        this.g = gVar;
        this.h = interfaceC0394k;
        this.i = hVar;
        this.j = interfaceC0388h;
        this.k = function1;
        this.l = i;
        this.m = i2;
        this.n = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.l | 1);
        int iH2 = C0776c.H(this.m);
        androidx.compose.ui.h hVar = this.i;
        int i = this.n;
        AbstractC3146g0.a(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, hVar, this.j, this.k, (InterfaceC0806l) obj, iH, iH2, i);
        return Unit.a;
    }
}
