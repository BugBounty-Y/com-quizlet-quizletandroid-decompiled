package com.braze;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.support.BrazeLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class n0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object a;
    public final /* synthetic */ BrazeUser b;
    public final /* synthetic */ String c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n0(BrazeUser brazeUser, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.b = brazeUser;
        this.c = str;
    }

    public static final String a(String str) {
        return AbstractC1476b.a("Successfully set LINE ID: ", str, '.');
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        n0 n0Var = new n0(this.b, this.c, hVar);
        n0Var.a = obj;
        return n0Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.a;
        com.braze.storage.h0 h0Var = this.b.userCache;
        String str = this.c;
        synchronized (h0Var) {
            h0Var.c("native_line_id", str);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.managers.C(this.c, 24), 6, (Object) null);
        return Unit.a;
    }
}
