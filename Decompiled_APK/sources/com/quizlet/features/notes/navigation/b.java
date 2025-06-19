package com.quizlet.features.notes.navigation;

import android.content.Context;
import com.google.android.gms.internal.mlkit_common.u;
import com.quizlet.data.model.m2;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.infra.navigation.B;
import com.quizlet.features.notes.upload.UploadNotesActivity;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class b implements B {
    public final Context a;

    public b(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.B
    public final void G() {
        int i = UploadNotesActivity.i;
        this.a.startActivity(u.i(this.a, m2.a, null, null, null, 12));
    }

    @Override // com.quizlet.features.infra.navigation.B
    public final void o(androidx.activity.result.b launcher, AddMaterialFolderData data) {
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        Intrinsics.checkNotNullParameter(data, "data");
        int i = UploadNotesActivity.i;
        launcher.a(u.i(this.a, m2.a, null, null, data, 12));
    }

    @Override // com.quizlet.features.infra.navigation.B
    public final void t(androidx.activity.result.b launcher, AddMaterialFolderData data) {
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        Intrinsics.checkNotNullParameter(data, "data");
        int i = UploadNotesActivity.i;
        launcher.a(u.i(this.a, m2.b, null, null, data, 12));
    }

    @Override // com.quizlet.features.infra.navigation.B
    public final void w() {
        int i = UploadNotesActivity.i;
        this.a.startActivity(u.i(this.a, m2.b, null, null, null, 12));
    }
}
