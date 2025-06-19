package com.quizlet.features.settings.composables.navigation;

import android.content.Context;
import android.content.Intent;
import androidx.fragment.app.I;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.oss.licenses.OssLicensesMenuActivity;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.quizlet.quizletandroid.R;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ com.quizlet.quizletandroid.ui.navigationmanagers.h l;
    public final /* synthetic */ Function0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(Function0 function0, com.quizlet.quizletandroid.ui.navigationmanagers.h hVar, Function0 function02, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = function0;
        this.l = hVar;
        this.m = function02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        g gVar = new g(this.k, this.l, this.m, hVar);
        gVar.j = obj;
        return gVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((com.quizlet.features.settings.data.events.h) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.settings.data.events.h hVar = (com.quizlet.features.settings.data.events.h) this.j;
        if (Intrinsics.b(hVar, com.quizlet.features.settings.data.events.a.a)) {
            this.k.invoke();
        } else {
            boolean zB = Intrinsics.b(hVar, com.quizlet.features.settings.data.events.c.a);
            com.quizlet.quizletandroid.ui.navigationmanagers.h hVar2 = this.l;
            if (zB) {
                hVar2.getClass();
                String str = UpgradeActivity.v;
                com.quizlet.features.infra.models.upgrade.a aVar2 = com.quizlet.features.infra.models.upgrade.a.g;
                Context context = hVar2.a;
                context.startActivity(AbstractC3242q6.i(context, "SettingsFragment", aVar2));
            } else if (Intrinsics.b(hVar, com.quizlet.features.settings.data.events.d.a)) {
                hVar2.getClass();
                String str2 = UpgradeActivity.v;
                com.quizlet.features.infra.models.upgrade.a aVar3 = com.quizlet.features.infra.models.upgrade.a.j;
                Context context2 = hVar2.a;
                context2.startActivity(AbstractC3242q6.i(context2, "OFFLINE_UPSELL_TAG", aVar3));
            } else if (Intrinsics.b(hVar, com.quizlet.features.settings.data.events.b.a)) {
                Context context3 = hVar2.a;
                OssLicensesMenuActivity.h = context3.getString(R.string.user_settings_attributions);
                context3.startActivity(new Intent(context3, (Class<?>) OssLicensesMenuActivity.class));
            } else if (hVar instanceof com.quizlet.features.settings.data.events.e) {
                com.quizlet.ui.models.webpage.b webPage = ((com.quizlet.features.settings.data.events.e) hVar).a;
                hVar2.getClass();
                Intrinsics.checkNotNullParameter(webPage, "webPage");
                com.quizlet.quizletandroid.ui.webpages.a.a.c(hVar2.a, webPage);
            } else if (Intrinsics.b(hVar, com.quizlet.features.settings.data.events.g.a)) {
                this.m.invoke();
            } else {
                if (!Intrinsics.b(hVar, com.quizlet.features.settings.data.events.f.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                Context context4 = hVar2.a;
                Intrinsics.e(context4, "null cannot be cast to non-null type androidx.fragment.app.FragmentActivity");
                I activity = (I) context4;
                com.quizlet.features.consent.onetrust.d dVar = hVar2.c;
                dVar.getClass();
                Intrinsics.checkNotNullParameter(activity, "activity");
                ((OTPublishersHeadlessSDK) dVar.b.get()).showPreferenceCenterUI(activity);
            }
        }
        return Unit.a;
    }
}
