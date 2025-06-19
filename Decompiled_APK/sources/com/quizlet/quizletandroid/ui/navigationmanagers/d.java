package com.quizlet.quizletandroid.ui.navigationmanagers;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.quizlet.features.emailconfirmation.ui.activities.EmailConfirmationActivity;
import com.quizlet.features.emailconfirmation.ui.activities.MagicLinkConfirmationActivity;
import com.quizlet.quizletandroid.ui.login.OldSignupActivity;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final Context a;
    public final com.quizlet.quizletandroid.util.g b;
    public final com.quizlet.quizletandroid.ui.debug.a c;

    public d(Context context, com.quizlet.quizletandroid.util.g loginBackstackManager, com.quizlet.quizletandroid.ui.debug.a devToolsManager) {
        com.quizlet.quizletandroid.ui.webpages.a webPageHelper = com.quizlet.quizletandroid.ui.webpages.a.a;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(webPageHelper, "webPageHelper");
        Intrinsics.checkNotNullParameter(loginBackstackManager, "loginBackstackManager");
        Intrinsics.checkNotNullParameter(devToolsManager, "devToolsManager");
        this.a = context;
        this.b = loginBackstackManager;
        this.c = devToolsManager;
    }

    public final void a() {
        String str = EmailConfirmationActivity.r;
        Context context = this.a;
        Intent intentA = D4.a(context, null);
        intentA.addFlags(268468224);
        Intent intentB = T.b(context, new Intent[]{intentA});
        intentB.addFlags(268468224);
        context.startActivity(intentB);
        ((Activity) context).finish();
    }

    public final void b() {
        Context context = this.a;
        Intrinsics.e(context, "null cannot be cast to non-null type android.app.Activity");
        this.b.getClass();
        com.quizlet.quizletandroid.util.g.a((Activity) context, null);
    }

    public final void c() {
        String str = MagicLinkConfirmationActivity.r;
        Context context = this.a;
        Intrinsics.checkNotNullParameter(context, "context");
        context.startActivity(new Intent(context, (Class<?>) MagicLinkConfirmationActivity.class));
        ((Activity) context).finish();
    }

    public final void d(String authToken, String authProvider) {
        Intrinsics.checkNotNullParameter(authToken, "oauthState");
        Intrinsics.checkNotNullParameter(authProvider, "authProvider");
        String str = OldSignupActivity.r;
        Context context = this.a;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(authToken, "authToken");
        Intrinsics.checkNotNullParameter(authProvider, "authProvider");
        Intent intent = new Intent(context, (Class<?>) OldSignupActivity.class);
        intent.putExtra("shouldSkipUpsell", false);
        intent.putExtra("shouldLaunchBirthdayFlow", true);
        intent.putExtra("birthdayAuthToken", authToken);
        intent.putExtra("birthdayAuthProvider", authProvider);
        intent.setAction("open_start_activity");
        context.startActivity(intent);
    }

    public final void e() {
        String str = UpgradeActivity.v;
        String str2 = OldSignupActivity.r;
        com.quizlet.features.infra.models.upgrade.a aVar = com.quizlet.features.infra.models.upgrade.a.f;
        Context context = this.a;
        Intent intentI = AbstractC3242q6.i(context, str2, aVar);
        intentI.setAction("open_start_activity");
        context.startActivity(intentI);
        ((Activity) context).finish();
    }
}
