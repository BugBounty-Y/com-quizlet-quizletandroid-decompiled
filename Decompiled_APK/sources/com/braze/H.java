package com.braze;

import androidx.compose.runtime.InterfaceC0773a0;
import com.appsflyer.AFInAppEventParameterName;
import com.appsflyer.AFInAppEventType;
import com.appsflyer.AppsFlyerLib;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3778z6;
import com.quizlet.data.model.B0;
import com.quizlet.remote.model.base.ApiPostBodySingle;
import com.quizlet.remote.model.explanations.myexplanations.RemoteMyExplanationsSession;
import java.math.BigDecimal;
import java.util.HashMap;
import java.util.Locale;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class H implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ H(Object obj, long j, Object obj2, int i) {
        this.a = i;
        this.c = obj;
        this.b = j;
        this.d = obj2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.logPushDelivery$lambda$201((Braze) this.c, (String) this.d, this.b);
            case 1:
                return com.braze.requests.framework.e.a((com.braze.requests.framework.h) this.c, this.b, (com.braze.models.response.d) this.d);
            case 2:
                return com.braze.requests.framework.e.a((com.braze.requests.framework.g) this.c, (com.braze.requests.framework.h) this.d, this.b);
            case 3:
                return com.braze.requests.framework.h.a((com.braze.requests.framework.h) this.c, (com.braze.requests.framework.i) this.d, this.b);
            case 4:
                return com.braze.requests.framework.queue.c.a((com.braze.requests.framework.h) this.c, this.b, (com.braze.requests.framework.h) this.d);
            case 5:
                com.quizlet.analytics.marketing.appsflyer.e eVar = (com.quizlet.analytics.marketing.appsflyer.e) ((com.quizlet.data.repository.classfolder.e) this.c).c;
                com.quizlet.data.model.billing.a details = (com.quizlet.data.model.billing.a) this.d;
                Intrinsics.checkNotNullParameter(details, "details");
                Pair pair = new Pair(AFInAppEventParameterName.CUSTOMER_USER_ID, Long.valueOf(this.b));
                Intrinsics.checkNotNullParameter(details, "<this>");
                Intrinsics.checkNotNullParameter(details, "<this>");
                long j = details.b;
                String str = details.c;
                Intrinsics.checkNotNullParameter(new com.quizlet.data.model.billing.c(j, str), "<this>");
                BigDecimal bigDecimalDivide = new BigDecimal(j).divide(BigDecimal.valueOf(1000000L));
                Intrinsics.checkNotNullExpressionValue(bigDecimalDivide, "divide(...)");
                Pair pair2 = new Pair(AFInAppEventParameterName.REVENUE, Double.valueOf(bigDecimalDivide.doubleValue()));
                Pair pair3 = new Pair(AFInAppEventParameterName.CURRENCY, str);
                Pair pair4 = new Pair(AFInAppEventParameterName.CONTENT_ID, details.a);
                String lowerCase = AbstractC3778z6.b(details).toString().toLowerCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
                HashMap mapE = kotlin.collections.V.e(pair, pair2, pair3, pair4, new Pair(AFInAppEventParameterName.CONTENT_TYPE, lowerCase), new Pair(AFInAppEventParameterName.PARAM_1, Boolean.valueOf(details.a())));
                AppsFlyerLib appsFlyerLib = AppsFlyerLib.getInstance();
                Intrinsics.checkNotNullExpressionValue(appsFlyerLib, "getInstance(...)");
                appsFlyerLib.logEvent(eVar.a, AFInAppEventType.PURCHASE, mapE);
                return Unit.a;
            case 6:
                com.quizlet.data.repository.explanations.myexplanations.a aVar = (com.quizlet.data.repository.explanations.myexplanations.a) ((com.quizlet.data.repository.folderset.c) this.c).b;
                B0 data = (B0) this.d;
                long j2 = this.b;
                aVar.getClass();
                Intrinsics.checkNotNullParameter(data, "item");
                C1721Kc c1721Kc = (C1721Kc) aVar.b;
                c1721Kc.getClass();
                Intrinsics.checkNotNullParameter(data, "item");
                Intrinsics.checkNotNullParameter(data, "data");
                RemoteMyExplanationsSession session = new RemoteMyExplanationsSession(j2, data.b(), data.getItemId(), 3, data.a(), false, 32, null);
                androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) c1721Kc.b;
                Intrinsics.checkNotNullParameter(session, "session");
                io.reactivex.rxjava3.core.a aVarD = ((com.quizlet.remote.service.l) cVar.b).d(new ApiPostBodySingle<>(session));
                Intrinsics.checkNotNullParameter(aVarD, "<this>");
                org.slf4j.b logger = (org.slf4j.b) aVar.c;
                Intrinsics.checkNotNullParameter(logger, "logger");
                Intrinsics.checkNotNullParameter("Error saving MyExplanationsItem to remote", "nonOfflineErrorMessage");
                com.google.firebase.crashlytics.internal.settings.b bVar = new com.google.firebase.crashlytics.internal.settings.b(logger, 5);
                aVarD.getClass();
                io.reactivex.rxjava3.internal.operators.completable.a aVar2 = new io.reactivex.rxjava3.internal.operators.completable.a(2, aVarD, bVar);
                Intrinsics.checkNotNullExpressionValue(aVar2, "onErrorResumeNext(...)");
                return aVar2;
            default:
                InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) this.d;
                interfaceC0773a0.setValue(Boolean.valueOf(!((Boolean) interfaceC0773a0.getValue()).booleanValue()));
                Long lValueOf = Long.valueOf(this.b);
                Boolean bool = (Boolean) interfaceC0773a0.getValue();
                bool.getClass();
                ((Function2) this.c).invoke(lValueOf, bool);
                return Unit.a;
        }
    }

    public /* synthetic */ H(Object obj, Object obj2, long j, int i) {
        this.a = i;
        this.c = obj;
        this.d = obj2;
        this.b = j;
    }
}
