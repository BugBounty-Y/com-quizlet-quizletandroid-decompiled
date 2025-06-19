package com.braze;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.enums.NotificationSubscriptionType;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class h0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ BrazeUser a;
    public final /* synthetic */ NotificationSubscriptionType b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h0(BrazeUser brazeUser, NotificationSubscriptionType notificationSubscriptionType, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = brazeUser;
        this.b = notificationSubscriptionType;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h0(this.a, this.b, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new h0(this.a, this.b, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        String strForJsonPut;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.braze.storage.h0 h0Var = this.a.userCache;
        NotificationSubscriptionType notificationSubscriptionType = this.b;
        synchronized (h0Var) {
            if (notificationSubscriptionType != null) {
                try {
                    strForJsonPut = notificationSubscriptionType.forJsonPut();
                } catch (Throwable th) {
                    throw th;
                }
            } else {
                strForJsonPut = null;
            }
            h0Var.c("email_subscribe", strForJsonPut);
        }
        return Unit.a;
    }
}
