package com.quizlet.upgrade.ui.navigation;

import android.content.Context;
import android.content.Intent;
import androidx.activity.result.b;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.quizlet.features.infra.navigation.A;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements A {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.A
    public final void i(String upgradeSource, com.quizlet.features.infra.models.upgrade.a navigationSource, b bVar) {
        Intrinsics.checkNotNullParameter(upgradeSource, "upgradeSource");
        Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
        String str = UpgradeActivity.v;
        Context context = this.a;
        Intent intentI = AbstractC3242q6.i(context, upgradeSource, navigationSource);
        if (bVar != null) {
            bVar.a(intentI);
        } else {
            context.startActivity(intentI);
        }
    }
}
