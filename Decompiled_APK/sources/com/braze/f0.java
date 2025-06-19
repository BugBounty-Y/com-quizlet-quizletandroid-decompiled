package com.braze;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ BrazeUser a;
    public final /* synthetic */ String b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f0(BrazeUser brazeUser, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = brazeUser;
        this.b = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f0(this.a, this.b, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new f0(this.a, this.b, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.braze.storage.h0 h0Var = this.a.userCache;
        String dateString = this.b;
        synchronized (h0Var) {
            Intrinsics.checkNotNullParameter(dateString, "dateString");
            h0Var.c("dob", dateString);
        }
        return Unit.a;
    }
}
