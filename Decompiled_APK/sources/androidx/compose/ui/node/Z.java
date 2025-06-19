package androidx.compose.ui.node;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class Z extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ a0 b;
    public final /* synthetic */ androidx.compose.ui.p c;
    public final /* synthetic */ C0908d d;
    public final /* synthetic */ long e;
    public final /* synthetic */ r f;
    public final /* synthetic */ boolean g;
    public final /* synthetic */ boolean h;
    public final /* synthetic */ float i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ Z(a0 a0Var, androidx.compose.ui.p pVar, C0908d c0908d, long j, r rVar, boolean z, boolean z2, float f, int i) {
        super(0);
        this.a = i;
        this.b = a0Var;
        this.c = pVar;
        this.d = c0908d;
        this.e = j;
        this.f = rVar;
        this.g = z;
        this.h = z2;
        this.i = f;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                androidx.compose.ui.p pVarE = AbstractC0910f.e(this.c, this.d.a());
                boolean z = this.h;
                a0 a0Var = this.b;
                C0908d c0908d = this.d;
                long j = this.e;
                r rVar = this.f;
                boolean z2 = this.g;
                if (pVarE == null) {
                    a0Var.b1(c0908d, j, rVar, z2, z);
                } else {
                    a0Var.getClass();
                    float f = this.i;
                    rVar.b(pVarE, f, z, new Z(a0Var, pVarE, c0908d, j, rVar, z2, z, f, 0));
                }
                break;
            default:
                this.b.m1(AbstractC0910f.e(this.c, this.d.a()), this.d, this.e, this.f, this.g, this.h, this.i);
                break;
        }
        return Unit.a;
    }
}
