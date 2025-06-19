package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.s4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0720s4 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ C0726t4 a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ float c;
    public final /* synthetic */ long d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0720s4(C0726t4 c0726t4, androidx.compose.ui.q qVar, float f, long j, int i) {
        super(2);
        this.a = c0726t4;
        this.b = qVar;
        this.c = f;
        this.d = j;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(1);
        this.a.a(this.b, this.c, this.d, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
