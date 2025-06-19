package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.i1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0633i1 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ float b;
    public final /* synthetic */ long c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0633i1(androidx.compose.ui.q qVar, float f, long j, int i) {
        super(2);
        this.a = qVar;
        this.b = f;
        this.c = j;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(1);
        long j = this.c;
        Z1.n(this.a, this.b, j, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
