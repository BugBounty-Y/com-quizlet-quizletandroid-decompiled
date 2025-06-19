package com.quizlet.quizletandroid.ui.live;

import android.graphics.drawable.Drawable;
import android.os.Bundle;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.firebase.crashlytics.internal.metadata.q;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4607k;
import com.quizlet.quizletandroid.ui.common.adapter.viewholder.h;
import com.quizlet.quizletandroid.ui.group.i;
import com.quizlet.uicommon.ui.common.dialogs.e;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class QuizletLiveActivity extends a {
    public static final /* synthetic */ int z = 0;
    public GoogleApiAvailability w;
    public androidx.camera.camera2.internal.concurrent.a x;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e y;

    public QuizletLiveActivity() {
        this.v = false;
        addOnContextAvailableListener(new i(this, 3));
        this.y = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(QuizletLiveViewModel.class), new c(this, 1), new c(this, 0), new c(this, 2));
    }

    public final QuizletLiveViewModel e0() {
        return (QuizletLiveViewModel) this.y.getValue();
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        if (!Intrinsics.b(e0().e.d(), Boolean.TRUE)) {
            super.onBackPressed();
            return;
        }
        e.a aVar = new e.a(this);
        aVar.b = false;
        aVar.f(R.string.leave_game_quizlet_live);
        aVar.c(R.string.you_may_not_be_able);
        aVar.e(R.string.leave_game, new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 8));
        aVar.d(R.string.cancel, new com.quizlet.infra.legacysyncengine.models.serializers.a(22));
        aVar.g();
    }

    @Override // com.quizlet.quizletandroid.ui.webpages.WebViewActivity, com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        final int i = 0;
        e0().e.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(10, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.live.b
            public final /* synthetic */ QuizletLiveActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                QuizletLiveActivity quizletLiveActivity = this.b;
                switch (i) {
                    case 0:
                        int i2 = QuizletLiveActivity.z;
                        quizletLiveActivity.runOnUiThread(new q(quizletLiveActivity, 15));
                        return Unit.a;
                    default:
                        int i3 = QuizletLiveActivity.z;
                        C4607k c4607k = (C4607k) quizletLiveActivity.K();
                        if (quizletLiveActivity.x == null) {
                            Intrinsics.m("imageCapturer");
                            throw null;
                        }
                        boolean zHasSystemFeature = quizletLiveActivity.getPackageManager().hasSystemFeature("android.hardware.camera.any");
                        QButton qButton = c4607k.c;
                        if (zHasSystemFeature) {
                            qButton.setVisibility(0);
                            qButton.setText(R.string.swap_to_qr_entry);
                            qButton.setOnClickListener(new h(quizletLiveActivity, 7));
                        } else {
                            qButton.setVisibility(8);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i2 = 1;
        e0().g.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(10, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.live.b
            public final /* synthetic */ QuizletLiveActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                QuizletLiveActivity quizletLiveActivity = this.b;
                switch (i2) {
                    case 0:
                        int i22 = QuizletLiveActivity.z;
                        quizletLiveActivity.runOnUiThread(new q(quizletLiveActivity, 15));
                        return Unit.a;
                    default:
                        int i3 = QuizletLiveActivity.z;
                        C4607k c4607k = (C4607k) quizletLiveActivity.K();
                        if (quizletLiveActivity.x == null) {
                            Intrinsics.m("imageCapturer");
                            throw null;
                        }
                        boolean zHasSystemFeature = quizletLiveActivity.getPackageManager().hasSystemFeature("android.hardware.camera.any");
                        QButton qButton = c4607k.c;
                        if (zHasSystemFeature) {
                            qButton.setVisibility(0);
                            qButton.setText(R.string.swap_to_qr_entry);
                            qButton.setOnClickListener(new h(quizletLiveActivity, 7));
                        } else {
                            qButton.setVisibility(8);
                        }
                        return Unit.a;
                }
            }
        }));
        QuizletLiveViewModel quizletLiveViewModelE0 = e0();
        com.quizlet.infra.legacysyncengine.managers.f fVar = Intrinsics.b(getIntent().getStringExtra("extra.url"), "https://quizlet.com/oauthweb/live") ? com.quizlet.infra.legacysyncengine.managers.f.b : com.quizlet.infra.legacysyncengine.managers.f.c;
        quizletLiveViewModelE0.getClass();
        Intrinsics.checkNotNullParameter(fVar, "<set-?>");
        quizletLiveViewModelE0.h = fVar;
        getWindow().addFlags(128);
        b0().getSettings().setJavaScriptEnabled(true);
        b0().addJavascriptInterface(e0().f, "androidLive");
    }

    @Override // com.quizlet.quizletandroid.ui.webpages.WebViewActivity, com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        C4607k c4607k = (C4607k) K();
        c4607k.e.setBackgroundColor(com.quizlet.themes.extensions.a.a(this, R.attr.SysColorBackground));
        ((C4607k) K()).e.setTitleTextColor(com.quizlet.themes.extensions.a.a(this, R.attr.SysColorBackground));
        Drawable drawable = getDrawable(R.drawable.ic_sys_close_x);
        if (drawable != null) {
            drawable.setTint(com.quizlet.themes.extensions.a.a(this, R.attr.AssemblyIconColor));
        }
        d0(drawable);
    }
}
