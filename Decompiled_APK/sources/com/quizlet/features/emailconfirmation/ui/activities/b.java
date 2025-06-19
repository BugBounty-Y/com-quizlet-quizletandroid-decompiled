package com.quizlet.features.emailconfirmation.ui.activities;

import android.content.Context;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_common.C2;
import com.quizlet.features.settings.SettingsActivity;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ EmailConfirmationActivity k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(EmailConfirmationActivity emailConfirmationActivity, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = emailConfirmationActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        b bVar = new b(this.k, hVar);
        bVar.j = obj;
        return bVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((com.quizlet.features.emailconfirmation.data.events.a) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        int iOrdinal = ((com.quizlet.features.emailconfirmation.data.events.a) this.j).ordinal();
        EmailConfirmationActivity emailConfirmationActivity = this.k;
        if (iOrdinal == 0) {
            com.quizlet.quizletandroid.ui.navigationmanagers.a aVar2 = emailConfirmationActivity.p;
            if (aVar2 == null) {
                Intrinsics.m("navigationManager");
                throw null;
            }
            int i = SettingsActivity.p;
            Context context = aVar2.a;
            context.startActivity(C2.c(context));
        } else {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            if (EmailConfirmationActivity.Q(emailConfirmationActivity).length != 0) {
                emailConfirmationActivity.startActivities(EmailConfirmationActivity.Q(emailConfirmationActivity));
            }
            emailConfirmationActivity.finish();
        }
        return Unit.a;
    }
}
