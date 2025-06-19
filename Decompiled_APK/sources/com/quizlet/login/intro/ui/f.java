package com.quizlet.login.intro.ui;

import android.content.Intent;
import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import com.appsflyer.AppsFlyerLib;
import com.google.firebase.messaging.p;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.CountryInfoDataWrapper;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.quizlet.login.intro.viewmodel.a j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(com.quizlet.login.intro.viewmodel.a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        int i = 3;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.login.intro.viewmodel.e eVar = (com.quizlet.login.intro.viewmodel.e) this.j;
        m0 m0Var = eVar.j;
        String str = (String) m0Var.a("magicLinkCode");
        if (str != null) {
            m0Var.b("magicLinkCode");
            E.A(p0.j(eVar), null, null, new com.quizlet.login.intro.viewmodel.d(eVar, str, null), 3);
        }
        Intent intent = eVar.k;
        if (intent != null) {
            p listener = new p(eVar, 29);
            com.quizlet.analytics.marketing.appsflyer.b bVar = eVar.c;
            bVar.getClass();
            Intrinsics.checkNotNullParameter(intent, "intent");
            Intrinsics.checkNotNullParameter(listener, "listener");
            AppsFlyerLib appsFlyerLib = AppsFlyerLib.getInstance();
            appsFlyerLib.subscribeForDeepLink(new com.google.firebase.tracing.a(i, bVar, listener));
            appsFlyerLib.performOnDeepLinking(intent, bVar.a);
        }
        final com.quizlet.quizletandroid.managers.g gVar = (com.quizlet.quizletandroid.managers.g) eVar.e;
        final int i2 = 0;
        final int i3 = 1;
        gVar.a.i().l(gVar.b).h(gVar.c).i(new io.reactivex.rxjava3.functions.d() { // from class: com.quizlet.quizletandroid.managers.d
            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj2) {
                switch (i2) {
                    case 0:
                        g gVar2 = gVar;
                        gVar2.getClass();
                        CountryInfoDataWrapper countryInfoDataWrapper = (CountryInfoDataWrapper) ((ApiThreeWrapper) ((K) obj2).b).getFirstData();
                        if (countryInfoDataWrapper != null) {
                            gVar2.e = countryInfoDataWrapper.getCountryInformation();
                            break;
                        }
                        break;
                    default:
                        gVar.getClass();
                        timber.log.c.a.a("Country information request failed: %s", ((Throwable) obj2).getMessage());
                        break;
                }
            }
        }, new io.reactivex.rxjava3.functions.d() { // from class: com.quizlet.quizletandroid.managers.d
            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj2) {
                switch (i3) {
                    case 0:
                        g gVar2 = gVar;
                        gVar2.getClass();
                        CountryInfoDataWrapper countryInfoDataWrapper = (CountryInfoDataWrapper) ((ApiThreeWrapper) ((K) obj2).b).getFirstData();
                        if (countryInfoDataWrapper != null) {
                            gVar2.e = countryInfoDataWrapper.getCountryInformation();
                            break;
                        }
                        break;
                    default:
                        gVar.getClass();
                        timber.log.c.a.a("Country information request failed: %s", ((Throwable) obj2).getMessage());
                        break;
                }
            }
        });
        E.A(p0.j(eVar), null, null, new com.quizlet.login.intro.viewmodel.b(eVar, null), 3);
        return Unit.a;
    }
}
