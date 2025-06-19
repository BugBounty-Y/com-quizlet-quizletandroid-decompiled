package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.google.android.gms.internal.mlkit_vision_common.C2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.quizlet.features.emailconfirmation.ui.activities.EmailConfirmationActivity;
import com.quizlet.features.settings.SettingsActivity;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String c;
    public final boolean a;
    public final boolean b;

    static {
        String simpleName = y.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        c = simpleName;
    }

    public y(boolean z, boolean z2) {
        this.a = z;
        this.b = z2;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (!this.a) {
            return new Intent[]{D4.a(context, GlobalNavReroute.Account.a)};
        }
        String str = EmailConfirmationActivity.r;
        Intent intentB = T.b(context, new Intent[]{D4.a(context, null)});
        int i = SettingsActivity.p;
        return new Intent[]{intentB, C2.c(context)};
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final boolean b() {
        return !this.b;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] c(Context context, h hVar) {
        return AbstractC3508o4.b(this, context, hVar);
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return c;
    }
}
