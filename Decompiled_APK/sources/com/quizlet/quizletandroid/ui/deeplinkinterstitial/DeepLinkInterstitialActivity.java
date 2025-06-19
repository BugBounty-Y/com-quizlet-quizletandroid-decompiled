package com.quizlet.quizletandroid.ui.deeplinkinterstitial;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import androidx.lifecycle.p0;
import com.quizlet.features.emailconfirmation.ui.activities.l;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class DeepLinkInterstitialActivity extends l implements com.quizlet.features.consent.onetrust.b {
    public static final String s;
    public com.quizlet.quizletandroid.managers.c p;
    public com.quizlet.quizletandroid.managers.deeplinks.h q;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e r;

    @Metadata
    public static final class DeepLinkException extends RuntimeException {
    }

    static {
        Intrinsics.checkNotNullExpressionValue("DeepLinkInterstitialActivity", "getSimpleName(...)");
        s = "DeepLinkInterstitialActivity";
    }

    public DeepLinkInterstitialActivity() {
        super(2);
        this.r = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(i.class), new e(this, 1), new e(this, 0), new e(this, 2));
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return s;
    }

    @Override // com.quizlet.features.emailconfirmation.ui.activities.l, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        E.A(p0.h(this), null, null, new d(this, null), 3);
        Intent intent = getIntent();
        Uri dataUri = intent.getData();
        if (!"android.intent.action.VIEW".equals(intent.getAction()) || dataUri == null) {
            return;
        }
        i iVar = (i) this.r.getValue();
        iVar.getClass();
        Intrinsics.checkNotNullParameter(dataUri, "dataUri");
        E.A(p0.j(iVar), null, null, new h(iVar, dataUri, null), 3);
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, android.app.Activity
    public final void onResume() {
        super.onResume();
        com.quizlet.quizletandroid.managers.c cVar = this.p;
        if (cVar == null) {
            Intrinsics.m("mConversionTrackingManager");
            throw null;
        }
        Context applicationContext = getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(applicationContext, "getApplicationContext(...)");
        cVar.a.a(new com.quizlet.quizletandroid.managers.a(applicationContext, getIntent().getData()));
    }

    @Override // com.quizlet.baseui.base.b
    public final int z() {
        return R.layout.activity_deep_link_interstitial;
    }
}
