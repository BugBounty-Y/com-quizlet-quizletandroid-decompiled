package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.u4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0741u4 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ long c;
    public final /* synthetic */ long d;
    public final /* synthetic */ float e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ androidx.compose.runtime.internal.d h;
    public final /* synthetic */ int i;
    public final /* synthetic */ int j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0741u4(int i, androidx.compose.ui.q qVar, long j, long j2, float f, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, int i2, int i3) {
        super(2);
        this.a = i;
        this.b = qVar;
        this.c = j;
        this.d = j2;
        this.e = f;
        this.f = dVar;
        this.g = dVar2;
        this.h = dVar3;
        this.i = i2;
        this.j = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.i | 1);
        androidx.compose.runtime.internal.d dVar = this.g;
        androidx.compose.runtime.internal.d dVar2 = this.h;
        androidx.compose.runtime.internal.d dVar3 = this.f;
        AbstractC0765y4.a(this.a, this.b, this.c, this.d, this.e, dVar3, dVar, dVar2, (InterfaceC0806l) obj, iH, this.j);
        return Unit.a;
    }
}
