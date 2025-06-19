package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0668k extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ long d;
    public final /* synthetic */ androidx.compose.foundation.N0 e;
    public final /* synthetic */ androidx.compose.ui.window.y f;
    public final /* synthetic */ androidx.compose.ui.graphics.V g;
    public final /* synthetic */ long h;
    public final /* synthetic */ float i;
    public final /* synthetic */ float j;
    public final /* synthetic */ androidx.compose.runtime.internal.d k;
    public final /* synthetic */ int l;
    public final /* synthetic */ int m;
    public final /* synthetic */ int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0668k(boolean z, Function0 function0, androidx.compose.ui.q qVar, long j, androidx.compose.foundation.N0 n0, androidx.compose.ui.window.y yVar, androidx.compose.ui.graphics.V v, long j2, float f, float f2, androidx.compose.runtime.internal.d dVar, int i, int i2, int i3) {
        super(2);
        this.a = z;
        this.b = function0;
        this.c = qVar;
        this.d = j;
        this.e = n0;
        this.f = yVar;
        this.g = v;
        this.h = j2;
        this.i = f;
        this.j = f2;
        this.k = dVar;
        this.l = i;
        this.m = i2;
        this.n = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.l | 1);
        int iH2 = C0776c.H(this.m);
        androidx.compose.runtime.internal.d dVar = this.k;
        float f = this.j;
        int i = this.n;
        AbstractC0686n.a(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, f, dVar, (InterfaceC0806l) obj, iH, iH2, i);
        return Unit.a;
    }
}
