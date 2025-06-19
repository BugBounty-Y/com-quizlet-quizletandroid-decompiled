package com.quizlet.quizletandroid.ui.live;

import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.managers.deeplinks.h;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.webpages.WebViewActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a extends WebViewActivity {
    public boolean v;

    @Override // com.quizlet.ads.ui.activity.d
    public final void a0() {
        if (this.v) {
            return;
        }
        this.v = true;
        QuizletLiveActivity quizletLiveActivity = (QuizletLiveActivity) this;
        C4622e c4622e = (C4622e) ((d) d());
        quizletLiveActivity.c = c4622e.a();
        u uVar = c4622e.b;
        quizletLiveActivity.e = uVar.Q0();
        quizletLiveActivity.q = (com.quizlet.db.token.a) uVar.u.get();
        uVar.D0();
        quizletLiveActivity.r = (com.quizlet.features.consent.onetrust.d) uVar.R0.get();
        com.quizlet.quizletandroid.deeplinks.a aVar = new com.quizlet.quizletandroid.deeplinks.a();
        com.quizlet.quizletandroid.deeplinks.a base36Converter = com.quizlet.quizletandroid.deeplinks.a.a;
        Intrinsics.checkNotNullParameter(base36Converter, "base36Converter");
        quizletLiveActivity.s = new com.quizlet.data.repository.login.a(aVar, new com.quizlet.quizletandroid.deeplinks.a(), (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get());
        quizletLiveActivity.t = new h();
        c4622e.e();
        GoogleApiAvailability googleApiAvailability = GoogleApiAvailability.d;
        Intrinsics.checkNotNullExpressionValue(googleApiAvailability, "getInstance(...)");
        S6.c(googleApiAvailability);
        quizletLiveActivity.w = googleApiAvailability;
        com.quizlet.quizletandroid.ui.common.images.capture.b profileImageCache = new com.quizlet.quizletandroid.ui.common.images.capture.b(0);
        Intrinsics.checkNotNullParameter(profileImageCache, "profileImageCache");
        quizletLiveActivity.x = new androidx.camera.camera2.internal.concurrent.a(profileImageCache);
    }

    @Override // com.quizlet.ads.ui.activity.d, dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.v;
    }
}
