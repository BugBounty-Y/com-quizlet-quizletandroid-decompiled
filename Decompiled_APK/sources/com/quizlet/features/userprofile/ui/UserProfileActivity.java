package com.quizlet.features.userprofile.ui;

import android.content.Intent;
import android.os.Bundle;
import androidx.activity.v;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class UserProfileActivity extends com.quizlet.features.achievements.ui.e {
    public static final String j;
    public com.quizlet.features.userprofile.navigation.b i;

    static {
        Intrinsics.checkNotNullExpressionValue("UserProfileActivity", "getSimpleName(...)");
        j = "UserProfileActivity";
    }

    public UserProfileActivity() {
        super(3);
    }

    @Override // com.quizlet.features.achievements.ui.e, com.quizlet.baseui.base.c, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        androidx.activity.compose.j.a(this, new androidx.compose.runtime.internal.d(true, 264892300, new com.quizlet.assembly.compose.cards.c(this, 22)));
        if (getIntent().getBooleanExtra("activityCenterReroute", false)) {
            Intent intent = getIntent();
            intent.removeExtra("activityCenterReroute");
            setIntent(intent);
            com.quizlet.features.userprofile.navigation.b bVar = this.i;
            if (bVar != null) {
                bVar.c();
            } else {
                Intrinsics.m("userProfileNavigationManager");
                throw null;
            }
        }
    }

    @Override // com.quizlet.baseui.base.c
    public final String y() {
        return j;
    }
}
