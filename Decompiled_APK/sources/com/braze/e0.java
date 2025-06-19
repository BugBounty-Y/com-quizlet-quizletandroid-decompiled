package com.braze;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ BrazeUser a;
    public final /* synthetic */ String b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e0(BrazeUser brazeUser, String str, Object obj, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = brazeUser;
        this.b = str;
        this.c = obj;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e0(this.a, this.b, this.c, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.braze.storage.h0 h0Var = this.a.userCache;
        String key = this.b;
        Object value = this.c;
        synchronized (h0Var) {
            Intrinsics.checkNotNullParameter(key, "key");
            Intrinsics.checkNotNullParameter(value, "value");
            h0Var.a(key, value);
        }
        return Unit.a;
    }
}
