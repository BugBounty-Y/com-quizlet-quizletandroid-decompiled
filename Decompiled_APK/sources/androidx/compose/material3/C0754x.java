package androidx.compose.material3;

import androidx.compose.foundation.layout.InterfaceC0388h;
import androidx.compose.foundation.layout.InterfaceC0394k;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0754x extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ InterfaceC0758x3 b;
    public final /* synthetic */ long c;
    public final /* synthetic */ long d;
    public final /* synthetic */ long e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;
    public final /* synthetic */ androidx.compose.ui.text.L g;
    public final /* synthetic */ float h;
    public final /* synthetic */ InterfaceC0394k i;
    public final /* synthetic */ InterfaceC0388h j;
    public final /* synthetic */ int k;
    public final /* synthetic */ boolean l;
    public final /* synthetic */ androidx.compose.runtime.internal.d m;
    public final /* synthetic */ androidx.compose.runtime.internal.d n;
    public final /* synthetic */ int o;
    public final /* synthetic */ int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0754x(androidx.compose.ui.q qVar, InterfaceC0758x3 interfaceC0758x3, long j, long j2, long j3, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.text.L l, float f, InterfaceC0394k interfaceC0394k, InterfaceC0388h interfaceC0388h, int i, boolean z, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, int i2, int i3) {
        super(2);
        this.a = qVar;
        this.b = interfaceC0758x3;
        this.c = j;
        this.d = j2;
        this.e = j3;
        this.f = dVar;
        this.g = l;
        this.h = f;
        this.i = interfaceC0394k;
        this.j = interfaceC0388h;
        this.k = i;
        this.l = z;
        this.m = dVar2;
        this.n = dVar3;
        this.o = i2;
        this.p = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.o | 1);
        int iH2 = C0776c.H(this.p);
        androidx.compose.runtime.internal.d dVar = this.n;
        androidx.compose.runtime.internal.d dVar2 = this.f;
        int i = this.k;
        boolean z = this.l;
        D.g(this.a, this.b, this.c, this.d, this.e, dVar2, this.g, this.h, this.i, this.j, i, z, this.m, dVar, (InterfaceC0806l) obj, iH, iH2);
        return Unit.a;
    }
}
