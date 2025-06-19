package androidx.compose.foundation.text;

import androidx.compose.foundation.gestures.C0326g0;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class D0 extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public int j;
    public /* synthetic */ C0326g0 k;
    public /* synthetic */ long l;
    public final /* synthetic */ kotlinx.coroutines.C m;
    public final /* synthetic */ InterfaceC0773a0 n;
    public final /* synthetic */ androidx.compose.foundation.interaction.l o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D0(kotlinx.coroutines.C c, InterfaceC0773a0 interfaceC0773a0, androidx.compose.foundation.interaction.l lVar, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.m = c;
        this.n = interfaceC0773a0;
        this.o = lVar;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        long j = ((androidx.compose.ui.geometry.b) obj2).a;
        D0 d0 = new D0(this.m, this.n, this.o, (kotlin.coroutines.h) obj3);
        d0.k = (C0326g0) obj;
        d0.l = j;
        return d0.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        kotlinx.coroutines.C c = this.m;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0326g0 c0326g0 = this.k;
            kotlinx.coroutines.E.A(c, null, null, new B0(this.n, this.l, this.o, null), 3);
            this.j = 1;
            obj = c0326g0.c(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        kotlinx.coroutines.E.A(c, null, null, new C0(this.n, ((Boolean) obj).booleanValue(), this.o, null), 3);
        return Unit.a;
    }
}
