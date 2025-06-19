package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.q3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0708q3 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;
    public final /* synthetic */ androidx.compose.runtime.internal.d c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ int f;
    public final /* synthetic */ long g;
    public final /* synthetic */ long h;
    public final /* synthetic */ androidx.compose.foundation.layout.R0 i;
    public final /* synthetic */ androidx.compose.runtime.internal.d j;
    public final /* synthetic */ int k;
    public final /* synthetic */ int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0708q3(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, int i, long j, long j2, androidx.compose.foundation.layout.R0 r0, androidx.compose.runtime.internal.d dVar5, int i2, int i3) {
        super(2);
        this.a = qVar;
        this.b = dVar;
        this.c = dVar2;
        this.d = dVar3;
        this.e = dVar4;
        this.f = i;
        this.g = j;
        this.h = j2;
        this.i = r0;
        this.j = dVar5;
        this.k = i2;
        this.l = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.k | 1);
        androidx.compose.runtime.internal.d dVar = this.j;
        long j = this.h;
        int i = this.l;
        AbstractC0725t3.a(this.a, this.b, this.c, this.d, this.e, this.f, this.g, j, this.i, dVar, (InterfaceC0806l) obj, iH, i);
        return Unit.a;
    }
}
