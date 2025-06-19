package com.quizlet.quizletandroid.ui.navigationmanagers;

import android.content.Context;
import android.content.Intent;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.generated.enums.A1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class e implements com.quizlet.features.notes.manager.a {
    public final Context a;

    public e(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    public static void a(e eVar, long j, A1 a1, Boolean bool, AddMaterialFolderData addMaterialFolderData, int i) {
        A1 a12 = (i & 2) != 0 ? null : a1;
        Boolean bool2 = (i & 8) != 0 ? null : bool;
        boolean z = (i & 16) != 0;
        AddMaterialFolderData addMaterialFolderData2 = (i & 32) != 0 ? null : addMaterialFolderData;
        eVar.getClass();
        eVar.b(com.quizlet.features.setpage.e.b(SetPageActivity.h1, eVar.a, j, a12, null, bool2, Boolean.valueOf(z), false, addMaterialFolderData2, 8));
    }

    public final void b(Intent intent) {
        intent.setFlags(268566528);
        this.a.startActivity(intent);
    }
}
