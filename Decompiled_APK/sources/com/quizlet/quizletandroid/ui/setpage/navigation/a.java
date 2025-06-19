package com.quizlet.quizletandroid.ui.setpage.navigation;

import android.content.Intent;
import androidx.activity.s;
import com.quizlet.features.setpage.navigation.b;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements b {
    public final void a(s activity, long j, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(activity, "activity");
        int i = EditSetActivity.M;
        Intent intent = new Intent(activity, (Class<?>) EditSetActivity.class);
        intent.putExtra("isFromHome", z);
        intent.putExtra("editSetActivityId", j);
        intent.putExtra("shouldFinishWithoutNewActivity", z2);
        intent.setFlags(603979776);
        activity.startActivityForResult(intent, 201);
    }
}
