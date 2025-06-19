package androidx.compose.material3.internal;

import androidx.compose.material.C0564g;
import androidx.compose.runtime.C0776c;
import androidx.datastore.core.C1087t;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.internal.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0645i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ kotlin.jvm.internal.r l;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C0645i(Function0 function0, Function2 function2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = (kotlin.jvm.internal.r) function0;
        this.m = (kotlin.coroutines.jvm.internal.i) function2;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0645i c0645i = new C0645i(this.l, this.m, hVar);
        c0645i.k = obj;
        return c0645i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0645i) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r5v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
            kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
            C1087t c1087tF = C0776c.F(this.l);
            C0564g c0564g = new C0564g(j, c, this.m, 1);
            this.j = 1;
            if (c1087tF.b(c0564g, this) == aVar) {
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
