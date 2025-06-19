package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.s3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0719s3 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;
    public final /* synthetic */ androidx.compose.runtime.internal.d c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ androidx.compose.foundation.layout.R0 f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0719s3(int i, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, androidx.compose.foundation.layout.R0 r0, androidx.compose.runtime.internal.d dVar5, int i2) {
        super(2);
        this.a = i;
        this.b = dVar;
        this.c = dVar2;
        this.d = dVar3;
        this.e = dVar4;
        this.f = r0;
        this.g = dVar5;
        this.h = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.h | 1);
        androidx.compose.runtime.internal.d dVar = this.c;
        androidx.compose.runtime.internal.d dVar2 = this.d;
        androidx.compose.runtime.internal.d dVar3 = this.e;
        AbstractC0725t3.b(this.a, this.b, dVar, dVar2, dVar3, this.f, this.g, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
