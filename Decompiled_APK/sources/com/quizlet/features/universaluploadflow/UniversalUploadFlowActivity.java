package com.quizlet.features.universaluploadflow;

import android.app.Activity;
import android.os.Bundle;
import androidx.activity.compose.j;
import androidx.activity.v;
import androidx.appcompat.app.C0054j;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class UniversalUploadFlowActivity extends com.quizlet.baseui.base.c implements dagger.hilt.internal.b {
    public static final /* synthetic */ int h = 0;
    public com.quizlet.login.authentication.login.a d;
    public volatile dagger.hilt.android.internal.managers.b e;
    public final Object f = new Object();
    public boolean g = false;

    public UniversalUploadFlowActivity() {
        addOnContextAvailableListener(new C0054j(this, 22));
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
        j.a(this, new androidx.compose.runtime.internal.d(true, -791583534, new a(this, 1)));
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
        return "UniversalUploadFlowActivity";
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
