package com.quizlet.quizletandroid;

import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.res.Resources;
import androidx.glance.appwidget.protobuf.Z;
import com.braze.Braze;
import com.braze.BrazeActivityLifecycleCallbackListener;
import com.braze.support.BrazeLogger;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3215n6;
import com.google.firebase.perf.metrics.Trace;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import java.util.Locale;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4593a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ androidx.compose.runtime.internal.j j;
    public final /* synthetic */ QuizletApplication k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4593a(androidx.compose.runtime.internal.j jVar, QuizletApplication quizletApplication, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = jVar;
        this.k = quizletApplication;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4593a(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4593a) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        String language;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        androidx.compose.runtime.internal.j jVar = this.j;
        com.quizlet.data.repository.qclass.c cVar = (com.quizlet.data.repository.qclass.c) jVar.c;
        Trace traceA = com.google.firebase.perf.b.a("startup_setupNotificationChannels");
        Context context = (Context) cVar.b;
        String string = context.getString(R.string.flashcard_auto_play_notification_channel_name);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        String string2 = context.getString(R.string.flashcard_auto_play_notification_channel_description);
        NotificationChannel notificationChannel = new NotificationChannel("no_sound_flashcard_auto_play_notification_channel", string, 2);
        if (string2 != null) {
            notificationChannel.setDescription(string2);
        }
        String string3 = context.getString(R.string.learn_notification_channel_name);
        Intrinsics.checkNotNullExpressionValue(string3, "getString(...)");
        NotificationChannel notificationChannelE = com.quizlet.data.repository.qclass.c.e("learn_notification_channel", 8, string3, context.getString(R.string.learn_notification_channel_description));
        String string4 = context.getString(R.string.content_recommendations_channel_name);
        Intrinsics.checkNotNullExpressionValue(string4, "getString(...)");
        NotificationChannel notificationChannelE2 = com.quizlet.data.repository.qclass.c.e("set_recommendation_channel", 8, string4, context.getString(R.string.content_recommendations_channel_description));
        String string5 = context.getString(R.string.default_notification_channel_name);
        Intrinsics.checkNotNullExpressionValue(string5, "getString(...)");
        ((NotificationManager) cVar.c).createNotificationChannels(kotlin.collections.B.j(notificationChannel, notificationChannelE, notificationChannelE2, com.quizlet.data.repository.qclass.c.e("miscellaneous_notification_channel", 12, string5, null)));
        traceA.stop();
        Trace traceA2 = com.google.firebase.perf.b.a("startup_initializeBrazeTrace");
        com.quizlet.braze.c cVar2 = (com.quizlet.braze.c) jVar.e;
        BrazeLogger.setLogLevel(cVar2.b());
        int iOrdinal = cVar2.a().ordinal();
        Context context2 = cVar2.a;
        if (iOrdinal == 0) {
            Braze.Companion.enableSdk(context2);
        } else if (iOrdinal == 1) {
            Braze.Companion.disableSdk(context2);
        } else if (iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        BrazeActivityLifecycleCallbackListener brazeActivityLifecycleCallbackListener = new BrazeActivityLifecycleCallbackListener(false, false, null, null, 15, null);
        QuizletApplication quizletApplication = this.k;
        quizletApplication.registerActivityLifecycleCallbacks(brazeActivityLifecycleCallbackListener);
        traceA2.stop();
        Trace traceA3 = com.google.firebase.perf.b.a("startup_initializeMarketingAnalytics");
        kotlinx.coroutines.E.A((kotlinx.coroutines.internal.d) jVar.j, null, null, new C4594b(jVar, quizletApplication, null), 3);
        traceA3.stop();
        Trace traceA4 = com.google.firebase.perf.b.a("startup_startConsentManager");
        com.quizlet.features.consent.onetrust.d dVar = (com.quizlet.features.consent.onetrust.d) jVar.g;
        dVar.getClass();
        Locale localeB = AbstractC3215n6.i(Resources.getSystem().getConfiguration()).b(0);
        if (localeB == null || (language = localeB.getLanguage()) == null) {
            language = "";
        }
        ((OTPublishersHeadlessSDK) dVar.b.get()).startSDK("cdn.cookielaw.org", "e9e75c89-d4be-40fa-a8f1-3fc0337bbd6e", language, dVar.a, new com.quizlet.data.interactor.course.a(dVar, 11));
        traceA4.stop();
        return Unit.a;
    }
}
