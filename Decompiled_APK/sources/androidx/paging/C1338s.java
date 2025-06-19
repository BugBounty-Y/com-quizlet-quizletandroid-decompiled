package androidx.paging;

import androidx.compose.animation.C0297y;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.paging.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1338s extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ InterfaceC4992i l;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C1338s(InterfaceC4992i interfaceC4992i, kotlin.jvm.functions.c cVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = interfaceC4992i;
        this.m = (kotlin.coroutines.jvm.internal.i) cVar;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1338s c1338s = new C1338s(this.l, this.m, hVar);
        c1338s.k = obj;
        return c1338s;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1338s) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r4v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            InterfaceC5002j interfaceC5002j = (InterfaceC5002j) this.k;
            kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
            j.a = AbstractC1348x.a;
            C0297y c0297y = new C0297y(j, (kotlin.jvm.functions.c) this.m, interfaceC5002j);
            this.j = 1;
            if (this.l.b(c0297y, this) == aVar) {
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
