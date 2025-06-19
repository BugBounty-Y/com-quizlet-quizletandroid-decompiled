package com.quizlet.quizletandroid.ui.live;

import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3721s5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.M5;
import com.quizlet.features.emailconfirmation.ui.activities.l;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.qrcodes.QLiveQrCodeReaderActivity;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class QuizletLiveDeepLinkInterstitialActivity extends l implements f, com.quizlet.features.consent.onetrust.b {
    public static final String s;
    public androidx.work.impl.model.e p;
    public androidx.work.impl.model.l q;
    public com.quizlet.infra.legacysyncengine.managers.d r;

    static {
        Intrinsics.checkNotNullExpressionValue("QuizletLiveDeepLinkInterstitialActivity", "getSimpleName(...)");
        s = "QuizletLiveDeepLinkInterstitialActivity";
    }

    public QuizletLiveDeepLinkInterstitialActivity() {
        super(6);
    }

    @Override // com.quizlet.quizletandroid.ui.live.f
    public final void A() {
        String str = QLiveQrCodeReaderActivity.t;
        startActivityForResult(M5.b(this), 1);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return s;
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, android.app.Activity
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i2 == 0) {
            finish();
            return;
        }
        if (i == 1) {
            String stringExtra = intent != null ? intent.getStringExtra("url_scanned") : null;
            androidx.work.impl.model.l lVar = this.q;
            if (lVar != null) {
                lVar.l(i2, stringExtra);
            } else {
                Intrinsics.m("entryPointPresenter");
                throw null;
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0071  */
    @Override // com.quizlet.features.emailconfirmation.ui.activities.l, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onCreate(android.os.Bundle r7) {
        /*
            r6 = this;
            super.onCreate(r7)
            androidx.work.impl.model.e r7 = r6.p
            java.lang.String r0 = "deepLinkInterstitialPresenter"
            r1 = 0
            if (r7 == 0) goto Ld6
            java.lang.String r2 = "view"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r2)
            r7.b = r6
            androidx.work.impl.model.l r7 = r6.q
            java.lang.String r3 = "entryPointPresenter"
            if (r7 == 0) goto Ld2
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r2)
            r7.c = r6
            java.lang.String r7 = "live.uri"
            java.lang.String[] r2 = new java.lang.String[]{r7}
            com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3197l6.b(r6, r2)
            android.content.Intent r2 = r6.getIntent()
            android.os.Parcelable r7 = r2.getParcelableExtra(r7)
            android.net.Uri r7 = (android.net.Uri) r7
            androidx.work.impl.model.e r2 = r6.p
            if (r2 == 0) goto Lce
            kotlin.jvm.internal.Intrinsics.d(r7)
            java.lang.String r0 = "uri"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r0)
            java.lang.String r7 = r7.toString()
            java.lang.String r0 = "toString(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r0)
            java.lang.String r0 = "rawUrl"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r0)
            java.lang.String r0 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r0)
            androidx.recyclerview.widget.j r0 = new androidx.recyclerview.widget.j
            r0.<init>()
            r0.l(r1, r7)
            okhttp3.s r7 = r0.d()
            java.util.ArrayList r7 = r7.f
            int r0 = r7.size()
            r4 = 2
            r5 = 1
            if (r0 < r4) goto L71
            java.lang.Object r7 = r7.get(r5)
            java.lang.String r7 = (java.lang.String) r7
            int r0 = r7.length()
            if (r0 <= 0) goto L71
            goto L72
        L71:
            r7 = r1
        L72:
            if (r7 == 0) goto L7e
            java.lang.Object r0 = r2.b
            com.quizlet.quizletandroid.ui.live.QuizletLiveDeepLinkInterstitialActivity r0 = (com.quizlet.quizletandroid.ui.live.QuizletLiveDeepLinkInterstitialActivity) r0
            if (r0 == 0) goto Lcd
            r0.s(r7)
            return
        L7e:
            java.lang.Object r7 = r2.b
            com.quizlet.quizletandroid.ui.live.QuizletLiveDeepLinkInterstitialActivity r7 = (com.quizlet.quizletandroid.ui.live.QuizletLiveDeepLinkInterstitialActivity) r7
            if (r7 == 0) goto Lcd
            androidx.work.impl.model.l r0 = r7.q
            if (r0 == 0) goto Lc9
            com.quizlet.infra.legacysyncengine.managers.d r2 = r7.r
            if (r2 == 0) goto Lc3
            com.quizlet.db.data.caches.UserInfoCache r1 = r2.e
            long r1 = r1.getPersonId()
            java.lang.Object r0 = r0.b
            com.quizlet.infra.legacysyncengine.managers.g r0 = (com.quizlet.infra.legacysyncengine.managers.g) r0
            com.quizlet.infra.legacysyncengine.managers.f r0 = r0.a(r1)
            java.lang.String r1 = "context"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r7, r1)
            java.lang.String r1 = "userLastJoinMethod"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            int r0 = r0.ordinal()
            if (r0 == 0) goto Lb9
            if (r0 != r5) goto Lb3
            java.lang.String r0 = com.quizlet.quizletandroid.ui.qrcodes.QLiveQrCodeReaderActivity.t
            android.content.Intent r0 = com.google.android.gms.internal.mlkit_vision_document_scanner.M5.b(r7)
            goto Lbf
        Lb3:
            kotlin.NoWhenBranchMatchedException r7 = new kotlin.NoWhenBranchMatchedException
            r7.<init>()
            throw r7
        Lb9:
            int r0 = com.quizlet.quizletandroid.ui.live.QuizletLiveActivity.z
            android.content.Intent r0 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3721s5.b(r7)
        Lbf:
            r7.startActivityForResult(r0, r5)
            return
        Lc3:
            java.lang.String r7 = "loggedInUserManager"
            kotlin.jvm.internal.Intrinsics.m(r7)
            throw r1
        Lc9:
            kotlin.jvm.internal.Intrinsics.m(r3)
            throw r1
        Lcd:
            return
        Lce:
            kotlin.jvm.internal.Intrinsics.m(r0)
            throw r1
        Ld2:
            kotlin.jvm.internal.Intrinsics.m(r3)
            throw r1
        Ld6:
            kotlin.jvm.internal.Intrinsics.m(r0)
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.live.QuizletLiveDeepLinkInterstitialActivity.onCreate(android.os.Bundle):void");
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStop() {
        super.onStop();
        androidx.work.impl.model.e eVar = this.p;
        if (eVar == null) {
            Intrinsics.m("deepLinkInterstitialPresenter");
            throw null;
        }
        ((io.reactivex.rxjava3.disposables.a) eVar.c).dispose();
        eVar.b = null;
    }

    @Override // com.quizlet.quizletandroid.ui.live.f
    public final void s(String gameCode) {
        Intrinsics.checkNotNullParameter(gameCode, "gameCode");
        int i = QuizletLiveActivity.z;
        startActivityForResult(AbstractC3721s5.c(this, gameCode), 1);
    }

    @Override // com.quizlet.quizletandroid.ui.live.f
    public final void w() {
        int i = QuizletLiveActivity.z;
        startActivityForResult(AbstractC3721s5.b(this), 1);
    }

    @Override // com.quizlet.baseui.base.b
    public final int z() {
        return R.layout.activity_quizlet_live_deep_link_interstitial;
    }
}
