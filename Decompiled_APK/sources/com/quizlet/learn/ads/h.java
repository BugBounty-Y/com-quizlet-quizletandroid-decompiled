package com.quizlet.learn.ads;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.quizlet.ads.data.AdDataType;
import io.reactivex.rxjava3.core.p;
import java.time.Duration;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements d {
    public static final long h = Duration.ofMinutes(5).toMillis();
    public final f a;
    public final com.google.firebase.crashlytics.internal.settings.b b;
    public final androidx.work.impl.model.c c;
    public AdDataType d;
    public boolean e;
    public final io.reactivex.rxjava3.subjects.d f;
    public final io.reactivex.rxjava3.disposables.a g;

    public h(f studyAdFetcher, com.google.firebase.crashlytics.internal.settings.b adsCountDownTimer, androidx.work.impl.model.c userProps, Context context) {
        com.quizlet.ads.c adUnit = com.quizlet.ads.c.h;
        Intrinsics.checkNotNullParameter(studyAdFetcher, "studyAdFetcher");
        Intrinsics.checkNotNullParameter(adsCountDownTimer, "adsCountDownTimer");
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(adUnit, "adUnit");
        this.a = studyAdFetcher;
        this.b = adsCountDownTimer;
        this.c = userProps;
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
        this.f = dVarZ;
        this.g = new io.reactivex.rxjava3.disposables.a();
        a(new com.quizlet.features.questionnaire.screens.c(this, context));
    }

    public final void a(Function0 function0) {
        androidx.work.impl.model.c cVar = this.c;
        p pVarO = p.o(cVar.q(), cVar.o(new com.quizlet.quizletandroid.config.features.properties.d(1), Boolean.FALSE), cVar.r(), a.b);
        Intrinsics.checkNotNullExpressionValue(pVarO, "zip(...)");
        this.g.b(B7.b(pVarO, new com.quizlet.features.universaluploadflow.flashcards.d(6), new com.quizlet.assembly.compose.input.d(13, function0)));
    }
}
