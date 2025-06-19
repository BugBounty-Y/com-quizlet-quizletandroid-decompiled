package androidx.datastore.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class I extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Function2 k;
    public final /* synthetic */ C1071c l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(Function2 function2, C1071c c1071c, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = function2;
        this.l = c1071c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new I(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((I) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
            return obj;
        }
        androidx.glance.appwidget.protobuf.Z.e(obj);
        Object obj2 = this.l.b;
        this.j = 1;
        Object objInvoke = this.k.invoke(obj2, this);
        return objInvoke == aVar ? aVar : objInvoke;
    }
}
