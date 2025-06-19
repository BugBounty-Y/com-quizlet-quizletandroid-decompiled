package androidx.compose.ui.node;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class Y extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ a0 a;
    public final /* synthetic */ androidx.compose.ui.p b;
    public final /* synthetic */ C0908d c;
    public final /* synthetic */ long d;
    public final /* synthetic */ r e;
    public final /* synthetic */ boolean f;
    public final /* synthetic */ boolean g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Y(a0 a0Var, androidx.compose.ui.p pVar, C0908d c0908d, long j, r rVar, boolean z, boolean z2) {
        super(0);
        this.a = a0Var;
        this.b = pVar;
        this.c = c0908d;
        this.d = j;
        this.e = rVar;
        this.f = z;
        this.g = z2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        this.a.Z0(AbstractC0910f.e(this.b, this.c.a()), this.c, this.d, this.e, this.f, this.g);
        return Unit.a;
    }
}
