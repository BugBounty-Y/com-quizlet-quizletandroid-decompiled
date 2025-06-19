package com.quizlet.security.challenge.core;

import android.content.Context;
import android.content.Intent;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.security.challenge.activity.SecurityChallengeActivity;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ i j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Boolean bool = (Boolean) obj;
        bool.booleanValue();
        return ((d) create(bool, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        i iVar = this.j;
        if (iVar.g < 3 || 300000 <= System.currentTimeMillis() - iVar.h) {
            if (300000 <= System.currentTimeMillis() - iVar.h) {
                timber.log.c.a.m("Resetting throttle window", new Object[0]);
                iVar.g = 0;
                iVar.h = System.currentTimeMillis();
            }
            Context context = iVar.a;
            Intent intent = new Intent(context, (Class<?>) SecurityChallengeActivity.class);
            intent.addFlags(268435456);
            context.startActivity(intent);
            iVar.g++;
        } else {
            iVar.e.b(com.quizlet.security.challenge.eventlogging.e.b);
            timber.log.c.a.o("Throttling challenge modal", new Object[0]);
        }
        return Unit.a;
    }
}
