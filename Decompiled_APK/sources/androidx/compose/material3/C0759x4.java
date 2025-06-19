package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.x4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0759x4 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;
    public final /* synthetic */ androidx.compose.ui.q c;
    public final /* synthetic */ long d;
    public final /* synthetic */ long e;
    public final /* synthetic */ float f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ androidx.compose.runtime.internal.d h;
    public final /* synthetic */ androidx.compose.foundation.N0 i;
    public final /* synthetic */ int j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0759x4(int i, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, long j, long j2, float f, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.foundation.N0 n0, int i2) {
        super(2);
        this.a = i;
        this.b = dVar;
        this.c = qVar;
        this.d = j;
        this.e = j2;
        this.f = f;
        this.g = dVar2;
        this.h = dVar3;
        this.i = n0;
        this.j = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.j | 1);
        androidx.compose.runtime.internal.d dVar = this.b;
        androidx.compose.runtime.internal.d dVar2 = this.g;
        androidx.compose.runtime.internal.d dVar3 = this.h;
        AbstractC0765y4.b(this.a, dVar, this.c, this.d, this.e, this.f, dVar2, dVar3, this.i, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
