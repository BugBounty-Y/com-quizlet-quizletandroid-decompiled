package com.quizlet.features.questionnaire.navigation;

import android.app.Activity;
import android.os.Bundle;
import androidx.activity.v;
import androidx.appcompat.app.C0054j;
import androidx.lifecycle.y0;
import com.amazon.device.ads.DtbDeviceData;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class QuestionnaireNavigationActivity extends com.quizlet.baseui.base.c implements dagger.hilt.internal.b {
    public static final /* synthetic */ int k = 0;
    public com.quizlet.login.authentication.login.a d;
    public volatile dagger.hilt.android.internal.managers.b e;
    public final Object f = new Object();
    public boolean g = false;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e h;
    public com.quizlet.features.questionnaire.steps.h i;
    public com.quizlet.data.interactor.course.a j;

    public QuestionnaireNavigationActivity() {
        addOnContextAvailableListener(new C0054j(this, 18));
        this.h = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(m.class), new d(this, 1), new d(this, 0), new d(this, 2));
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
        B(bundle);
        v.b(this, null, 3);
        QuestionnaireModel model = (QuestionnaireModel) androidx.core.content.c.e(getIntent(), DtbDeviceData.DEVICE_DATA_MODEL_KEY, QuestionnaireModel.class);
        if (model != null) {
            m mVar = (m) ((b) this.h.getValue());
            mVar.getClass();
            Intrinsics.checkNotNullParameter(model, "model");
            mVar.b.c(model, DtbDeviceData.DEVICE_DATA_MODEL_KEY);
            mVar.f.clear();
            Boolean bool = Boolean.TRUE;
            s0 s0Var = mVar.e;
            s0Var.getClass();
            s0Var.m(null, bool);
            mVar.B(model.a);
        }
        androidx.activity.compose.j.a(this, new androidx.compose.runtime.internal.d(true, -2083276185, new c(this, 1)));
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
        return "QuestionnaireNavigationActivity";
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
