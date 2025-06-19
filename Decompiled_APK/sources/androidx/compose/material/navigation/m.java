package androidx.compose.material.navigation;

import androidx.compose.animation.C0297y;
import androidx.compose.animation.core.K;
import androidx.compose.material.e0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import androidx.navigation.C1291m;
import androidx.paging.C1306b0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ e0 k;
    public final /* synthetic */ C1291m l;
    public final /* synthetic */ InterfaceC0773a0 m;
    public final /* synthetic */ InterfaceC0773a0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(e0 e0Var, C1291m c1291m, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = e0Var;
        this.l = c1291m;
        this.m = interfaceC0773a0;
        this.n = interfaceC0773a02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new m(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((m) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C1306b0 c1306b0N = kotlinx.coroutines.flow.e0.n(kotlinx.coroutines.flow.e0.m(C0776c.F(new K(this.k, 17))), 1);
            C0297y c0297y = new C0297y(this.l, this.m, this.n);
            this.j = 1;
            if (c1306b0N.b(c0297y, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
