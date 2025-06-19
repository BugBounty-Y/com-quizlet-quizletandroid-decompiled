package androidx.compose.foundation.gestures;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class H0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public L0 j;
    public kotlin.jvm.internal.I k;
    public long l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ L0 o;
    public final /* synthetic */ kotlin.jvm.internal.I p;
    public final /* synthetic */ long q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public H0(L0 l0, kotlin.jvm.internal.I i, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.o = l0;
        this.p = i;
        this.q = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        H0 h0 = new H0(this.o, this.p, this.q, hVar);
        h0.n = obj;
        return h0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((H0) create((I0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        L0 l0;
        kotlin.jvm.internal.I i;
        long j;
        L0 l02;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i2 = this.m;
        EnumC0320d0 enumC0320d0 = EnumC0320d0.b;
        if (i2 == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            I0 i0 = (I0) this.n;
            l0 = this.o;
            G0 g0 = new G0(l0, i0);
            InterfaceC0314a0 interfaceC0314a0 = l0.c;
            i = this.p;
            long j2 = i.a;
            EnumC0320d0 enumC0320d02 = l0.d;
            long j3 = this.q;
            float fC = l0.c(enumC0320d02 == enumC0320d0 ? androidx.compose.ui.unit.o.b(j3) : androidx.compose.ui.unit.o.c(j3));
            this.n = l0;
            this.j = l0;
            this.k = i;
            this.l = j2;
            this.m = 1;
            obj = interfaceC0314a0.a(g0, fC, this);
            if (obj == aVar) {
                return aVar;
            }
            j = j2;
            l02 = l0;
        } else {
            if (i2 != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            j = this.l;
            i = this.k;
            l0 = this.j;
            l02 = (L0) this.n;
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        float fC2 = l02.c(((Number) obj).floatValue());
        i.a = l0.d == enumC0320d0 ? androidx.compose.ui.unit.o.a(j, fC2, DefinitionKt.NO_Float_VALUE, 2) : androidx.compose.ui.unit.o.a(j, DefinitionKt.NO_Float_VALUE, fC2, 1);
        return Unit.a;
    }
}
