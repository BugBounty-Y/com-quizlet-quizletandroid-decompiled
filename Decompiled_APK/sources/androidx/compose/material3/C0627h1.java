package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.h1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0627h1 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ float c;
    public final /* synthetic */ long d;
    public final /* synthetic */ int e;
    public final /* synthetic */ int f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0627h1(androidx.compose.ui.q qVar, float f, long j, int i, int i2, int i3) {
        super(2);
        this.a = i3;
        this.b = qVar;
        this.c = f;
        this.d = j;
        this.e = i;
        this.f = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.e | 1);
                androidx.compose.ui.q qVar = this.b;
                Z1.e(qVar, this.c, this.d, (InterfaceC0806l) obj, iH, this.f);
                break;
            default:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.e | 1);
                androidx.compose.ui.q qVar2 = this.b;
                Z1.g(qVar2, this.c, this.d, (InterfaceC0806l) obj, iH2, this.f);
                break;
        }
        return Unit.a;
    }
}
