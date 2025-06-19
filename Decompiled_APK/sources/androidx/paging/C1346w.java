package androidx.paging;

import androidx.compose.foundation.text.input.internal.C0496b;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* renamed from: androidx.paging.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1346w extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ InterfaceC4992i l;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C1346w(InterfaceC4992i interfaceC4992i, kotlin.jvm.functions.c cVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = interfaceC4992i;
        this.m = (kotlin.coroutines.jvm.internal.i) cVar;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1346w c1346w = new C1346w(this.l, this.m, hVar);
        c1346w.k = obj;
        return c1346w;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1346w) create((a1) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.c] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C1344v c1344v = new C1344v(this.m, new C0496b((a1) this.k), null);
            this.j = 1;
            if (kotlinx.coroutines.flow.e0.i(this.l, c1344v, this) == aVar) {
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
