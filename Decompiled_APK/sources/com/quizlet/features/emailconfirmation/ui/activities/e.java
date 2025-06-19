package com.quizlet.features.emailconfirmation.ui.activities;

import android.content.Intent;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ EmailConfirmationActivity j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(EmailConfirmationActivity emailConfirmationActivity, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = emailConfirmationActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((Unit) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.quizletandroid.ui.navigationmanagers.a aVar2 = this.j.p;
        if (aVar2 == null) {
            Intrinsics.m("navigationManager");
            throw null;
        }
        aVar2.a.startActivity((Intent) aVar2.b.get());
        return Unit.a;
    }
}
