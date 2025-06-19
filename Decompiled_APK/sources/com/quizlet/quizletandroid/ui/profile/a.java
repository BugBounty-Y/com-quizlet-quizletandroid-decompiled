package com.quizlet.quizletandroid.ui.profile;

import android.content.Context;
import android.content.Intent;
import com.quizlet.features.infra.navigation.InterfaceC4343c;
import com.quizlet.quizletandroid.ui.usersettings.activities.ChangeProfileImageActivity;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements InterfaceC4343c {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.InterfaceC4343c
    public final void a(String profileImageId, boolean z, androidx.activity.result.b launcher) {
        Intrinsics.checkNotNullParameter(profileImageId, "profileImageId");
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        int i = ChangeProfileImageActivity.q;
        Intent intent = new Intent(this.a, (Class<?>) ChangeProfileImageActivity.class);
        intent.putExtra("EXTRA_PROFILE_IMAGE_ID", profileImageId);
        intent.putExtra("EXTRA_ALLOW_CUSTOM_IMAGES", z);
        launcher.a(intent);
    }
}
