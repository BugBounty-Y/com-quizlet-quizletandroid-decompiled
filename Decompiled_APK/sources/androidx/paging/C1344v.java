package androidx.paging;

import androidx.compose.foundation.text.input.internal.C0496b;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.paging.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1344v extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i l;
    public final /* synthetic */ C0496b m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C1344v(kotlin.jvm.functions.c cVar, C0496b c0496b, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = (kotlin.coroutines.jvm.internal.i) cVar;
        this.m = c0496b;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1344v c1344v = new C1344v(this.l, this.m, hVar);
        c1344v.k = obj;
        return c1344v;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1344v) create(obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            Object obj2 = this.k;
            this.j = 1;
            if (this.l.invoke(this.m, obj2, this) == aVar) {
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
