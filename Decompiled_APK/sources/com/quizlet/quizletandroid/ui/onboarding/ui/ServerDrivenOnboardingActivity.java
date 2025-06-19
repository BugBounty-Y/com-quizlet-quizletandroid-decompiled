package com.quizlet.quizletandroid.ui.onboarding.ui;

import android.app.Activity;
import android.os.Bundle;
import androidx.activity.compose.j;
import androidx.activity.v;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.features.questionnaire.navigation.QuestionnaireModel;
import com.quizlet.quizletandroid.ui.group.i;
import com.quizlet.quizletandroid.ui.onboarding.d;
import com.quizlet.quizletandroid.ui.onboarding.f;
import com.quizlet.quizletandroid.ui.onboarding.h;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class ServerDrivenOnboardingActivity extends com.quizlet.baseui.base.c implements dagger.hilt.internal.b {
    public static final /* synthetic */ int i = 0;
    public com.quizlet.login.authentication.login.a d;
    public volatile dagger.hilt.android.internal.managers.b e;
    public final Object f = new Object();
    public boolean g = false;
    public final e h;

    public ServerDrivenOnboardingActivity() {
        addOnContextAvailableListener(new i(this, 8));
        this.h = new e(K.a(h.class), new b(this, 1), new b(this, 0), new b(this, 2));
    }

    public final void B(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = z().b();
            this.d = aVarB;
            if (aVarB.l()) {
                this.d.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return z().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.c, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        s0 s0Var;
        Object value;
        B(bundle);
        v.b(this, null, 3);
        QuestionnaireModel questionnaireModel = (QuestionnaireModel) androidx.core.content.c.e(getIntent(), "EXTRA_MODEL", QuestionnaireModel.class);
        if (questionnaireModel != null) {
            h hVar = (h) this.h.getValue();
            com.quizlet.quizletandroid.ui.onboarding.c event = new com.quizlet.quizletandroid.ui.onboarding.c(questionnaireModel);
            hVar.getClass();
            Intrinsics.checkNotNullParameter(event, "event");
            hVar.b.c(questionnaireModel, "questionnaire_model");
            f currentStep = new f(questionnaireModel);
            do {
                s0Var = hVar.d;
                value = s0Var.getValue();
                ((d) value).getClass();
                Intrinsics.checkNotNullParameter(currentStep, "currentStep");
            } while (!s0Var.k(value, new d(currentStep, null)));
        }
        j.a(this, new androidx.compose.runtime.internal.d(true, 1889467241, new a(this, 1)));
    }

    @Override // com.quizlet.baseui.base.c, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.d;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // com.quizlet.baseui.base.c
    public final String y() {
        return "ServerDrivenOnboardingActivity";
    }

    public final dagger.hilt.android.internal.managers.b z() {
        if (this.e == null) {
            synchronized (this.f) {
                try {
                    if (this.e == null) {
                        this.e = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.e;
    }
}
