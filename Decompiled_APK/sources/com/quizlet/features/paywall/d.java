package com.quizlet.features.paywall;

import android.content.Context;
import android.content.Intent;
import com.quizlet.features.infra.navigation.q;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class d implements q {
    public final Context a;

    public d(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.q
    public final void b(String upgradeSource, com.quizlet.features.infra.models.upgrade.a navigationSource) {
        Intrinsics.checkNotNullParameter(upgradeSource, "upgradeSource");
        Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
        int i = PaywallActivity.l;
        int i2 = navigationSource.a;
        Context context = this.a;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(upgradeSource, "upgradeSource");
        Intent intent = new Intent(context, (Class<?>) PaywallActivity.class);
        intent.putExtra("upgradeSource", upgradeSource);
        intent.putExtra("navigationSource", i2);
        context.startActivity(intent);
    }
}
