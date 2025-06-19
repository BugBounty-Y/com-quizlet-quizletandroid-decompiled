package androidx.compose.animation;

import androidx.compose.animation.core.E0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0807l0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.datastore.core.C1087t;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.animation.z, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0298z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ E0 l;
    public final /* synthetic */ InterfaceC0773a0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0298z(E0 e0, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = e0;
        this.m = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0298z c0298z = new C0298z(this.l, this.m, hVar);
        c0298z.k = obj;
        return c0298z;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0298z) create((C0807l0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0807l0 c0807l0 = (C0807l0) this.k;
            E0 e0 = this.l;
            C1087t c1087tF = C0776c.F(new C0296x(e0, 0));
            C0297y c0297y = new C0297y(c0807l0, e0, this.m, 0);
            this.j = 1;
            if (c1087tF.b(c0297y, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
