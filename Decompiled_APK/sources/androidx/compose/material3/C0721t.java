package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0721t extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.runtime.internal.d a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ androidx.compose.runtime.internal.d c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ float e;
    public final /* synthetic */ androidx.compose.foundation.layout.R0 f;
    public final /* synthetic */ V4 g;
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0721t(androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, float f, androidx.compose.foundation.layout.R0 r0, V4 v4, int i) {
        super(2);
        this.a = dVar;
        this.b = qVar;
        this.c = dVar2;
        this.d = dVar3;
        this.e = f;
        this.f = r0;
        this.g = v4;
        this.h = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.h | 1);
        V4 v4 = this.g;
        androidx.compose.runtime.internal.d dVar = this.a;
        androidx.compose.runtime.internal.d dVar2 = this.c;
        float f = this.e;
        androidx.compose.foundation.layout.R0 r0 = this.f;
        D.e(dVar, this.b, dVar2, this.d, f, r0, v4, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
