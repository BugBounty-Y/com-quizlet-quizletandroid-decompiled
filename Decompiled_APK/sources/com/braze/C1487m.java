package com.braze;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.events.IValueCallback;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;

/* renamed from: com.braze.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1487m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int a;
    public final /* synthetic */ IValueCallback b;
    public final /* synthetic */ Braze c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1487m(IValueCallback iValueCallback, Braze braze, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.b = iValueCallback;
        this.c = braze;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1487m(this.b, this.c, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new C1487m(this.b, this.c, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.a;
        if (i == 0) {
            Z.e(obj);
            CoroutineContext coroutineContext = BrazeCoroutineScope.INSTANCE.getCoroutineContext();
            C1486l c1486l = new C1486l(this.b, this.c, null);
            this.a = 1;
            if (kotlinx.coroutines.E.J(coroutineContext, c1486l, this) == aVar) {
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
