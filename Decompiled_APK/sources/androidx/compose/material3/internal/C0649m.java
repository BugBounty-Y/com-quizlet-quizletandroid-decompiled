package androidx.compose.material3.internal;

import androidx.compose.material.C0574q;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.internal.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0649m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0574q l;
    public final /* synthetic */ androidx.work.impl.model.t m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0649m(C0574q c0574q, androidx.work.impl.model.t tVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0574q;
        this.m = tVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0649m c0649m = new C0649m(this.l, this.m, hVar);
        c0649m.k = obj;
        return c0649m;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0649m) create((F) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            F f = (F) this.k;
            r rVar = (r) this.m.n;
            this.j = 1;
            if (this.l.invoke(rVar, f, this) == aVar) {
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
