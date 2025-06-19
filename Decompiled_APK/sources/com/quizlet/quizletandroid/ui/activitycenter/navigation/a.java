package com.quizlet.quizletandroid.ui.activitycenter.navigation;

import android.content.Context;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.I;
import com.quizlet.features.infra.navigation.InterfaceC4342b;
import com.quizlet.quizletandroid.ui.activitycenter.fragments.ActivityCenterModalFragment;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements InterfaceC4342b {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.InterfaceC4342b
    public final void c() {
        Context context = this.a;
        Intrinsics.e(context, "null cannot be cast to non-null type androidx.fragment.app.FragmentActivity");
        AbstractC1136h0 supportFragmentManager = ((I) context).getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "getSupportFragmentManager(...)");
        new ActivityCenterModalFragment().O(supportFragmentManager, ActivityCenterModalFragment.K);
    }
}
