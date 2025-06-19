package com.quizlet.features.setpage;

import android.content.Context;
import android.content.Intent;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.generated.enums.A1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

/* loaded from: classes3.dex */
public final class e {
    public static Intent b(e eVar, Context context, long j, A1 a1, Double d, Boolean bool, Boolean bool2, boolean z, AddMaterialFolderData addMaterialFolderData, int i) {
        if ((i & 4) != 0) {
            a1 = null;
        }
        if ((i & 8) != 0) {
            d = null;
        }
        if ((i & 16) != 0) {
            bool = null;
        }
        if ((i & 32) != 0) {
            bool2 = null;
        }
        if ((i & 64) != 0) {
            z = false;
        }
        if ((i & 128) != 0) {
            addMaterialFolderData = null;
        }
        eVar.getClass();
        Intrinsics.checkNotNullParameter(context, "context");
        Intent intent = new Intent(context, (Class<?>) SetPageActivity.class);
        intent.setAction(K.a(SetPageActivity.class).e() + "_" + j);
        intent.putExtra("setId", j);
        if (a1 != null) {
            intent.putExtra("studyMode", a1);
        }
        if (d != null) {
            intent.putExtra("matchHighScore", d.doubleValue());
        }
        if (bool != null) {
            intent.putExtra("isNewStudySet", bool.booleanValue());
        }
        if (addMaterialFolderData != null) {
            intent.putExtra("addMaterialFolderData", addMaterialFolderData);
        }
        intent.putExtra("isFromHome", false);
        intent.putExtra("shouldGoToEditSet", z);
        intent.putExtra("shouldDismissAfterStudyModeFinished", bool2);
        return intent;
    }

    public static Intent c(int i, long j, Context context) {
        e eVar = SetPageActivity.h1;
        Intrinsics.checkNotNullParameter(context, "context");
        Intent intentB = b(eVar, context, j, null, null, null, null, false, null, 224);
        intentB.putExtra("isFromHome", true);
        return intentB;
    }

    public final Intent a(Context context, long j, boolean z) {
        Intrinsics.checkNotNullParameter(context, "context");
        return b(this, context, j, null, null, Boolean.valueOf(z), null, false, null, 224);
    }
}
