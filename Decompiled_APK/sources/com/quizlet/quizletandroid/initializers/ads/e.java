package com.quizlet.quizletandroid.initializers.ads;

import android.app.Activity;
import android.util.AndroidRuntimeException;
import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.J0;
import com.amazon.device.ads.AdRegistration;
import com.google.android.gms.ads.MobileAds;
import com.google.firebase.perf.metrics.Trace;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.W;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public Activity j;
    public J0 k;
    public int l;
    public final /* synthetic */ u m;
    public final /* synthetic */ MobileAdsInitializer n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(u uVar, MobileAdsInitializer mobileAdsInitializer, h hVar) {
        super(2, hVar);
        this.m = uVar;
        this.n = mobileAdsInitializer;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r9v4, types: [kotlinx.coroutines.flow.i, kotlinx.coroutines.flow.internal.a] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Activity activity;
        J0 j0;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.l;
        u uVar = this.m;
        MobileAdsInitializer mobileAdsInitializer = this.n;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.features.flashcards.helpers.d dVar = new com.quizlet.features.flashcards.helpers.d(((com.quizlet.usecase.a) uVar.V0.get()).a, 5);
            b bVar = new b(2, null);
            this.l = 1;
            obj = e0.q(dVar, bVar, this);
            if (obj != aVar) {
            }
            return aVar;
        }
        if (i != 1) {
            if (i != 2) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            j0 = this.k;
            activity = this.j;
            Z.e(obj);
            mobileAdsInitializer.getClass();
            Trace traceA = com.google.firebase.perf.b.a("initializeAmazonTamAds");
            try {
                AdRegistration.getInstance(activity.getString(R.string.amazon_tam_ads), activity);
            } catch (IllegalArgumentException e) {
                timber.log.c.a.f(e, "Failed to initialize Amazon TAM Ads", new Object[0]);
            }
            traceA.stop();
            com.quizlet.features.questionnaire.screens.c cVar = new com.quizlet.features.questionnaire.screens.c(21, j0, uVar);
            Trace traceA2 = com.google.firebase.perf.b.a("initializeMobileAds");
            try {
                MobileAds.a(activity, new a(cVar));
            } catch (AndroidRuntimeException e2) {
                timber.log.c.a.f(e2, "Failed to initialize Mobile Ads", new Object[0]);
            }
            traceA2.stop();
            return Unit.a;
        }
        Z.e(obj);
        activity = (Activity) obj;
        J0 j02 = new J0(e0.m(new com.quizlet.analytics.marketing.appsflyer.d((W) ((com.quizlet.usecase.a) uVar.o.get()).a, 3)), new c(mobileAdsInitializer, null), 5);
        this.j = activity;
        this.k = j02;
        this.l = 2;
        if (e0.p(j02, this) != aVar) {
            j0 = j02;
            mobileAdsInitializer.getClass();
            Trace traceA3 = com.google.firebase.perf.b.a("initializeAmazonTamAds");
            AdRegistration.getInstance(activity.getString(R.string.amazon_tam_ads), activity);
            traceA3.stop();
            com.quizlet.features.questionnaire.screens.c cVar2 = new com.quizlet.features.questionnaire.screens.c(21, j0, uVar);
            Trace traceA22 = com.google.firebase.perf.b.a("initializeMobileAds");
            MobileAds.a(activity, new a(cVar2));
            traceA22.stop();
            return Unit.a;
        }
        return aVar;
    }
}
