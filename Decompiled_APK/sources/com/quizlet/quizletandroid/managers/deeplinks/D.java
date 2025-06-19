package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class D implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String b;
    public final boolean a;

    static {
        String simpleName = D.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        b = simpleName;
    }

    public D(boolean z) {
        this.a = z;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        String str = UpgradeActivity.v;
        Intent intentI = AbstractC3242q6.i(context, "DeepLink", com.quizlet.features.infra.models.upgrade.a.k);
        intentI.setFlags(67108864);
        intentI.setAction(this.a ? "require_email_confirmation" : "open_start_activity");
        return new Intent[]{intentI};
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final boolean b() {
        return true;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] c(Context context, h hVar) {
        return AbstractC3508o4.b(this, context, hVar);
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return b;
    }
}
