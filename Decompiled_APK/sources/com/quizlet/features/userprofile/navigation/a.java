package com.quizlet.features.userprofile.navigation;

import android.content.Context;
import android.content.Intent;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.infra.navigation.l;
import com.quizlet.features.userprofile.ui.UserProfileActivity;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements l {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.l
    public final void m() {
        String str = UserProfileActivity.j;
        Context context = this.a;
        Intent intentB = AbstractC4178x.b(context, "context", context, UserProfileActivity.class);
        intentB.putExtra("activityCenterReroute", false);
        context.startActivity(intentB);
    }
}
