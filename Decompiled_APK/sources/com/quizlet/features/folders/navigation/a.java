package com.quizlet.features.folders.navigation;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3309z0;
import com.quizlet.features.folders.FolderActivity;
import com.quizlet.features.infra.navigation.j;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements j {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.j
    public final void v(long j) {
        String str = FolderActivity.j;
        Context context = this.a;
        context.startActivity(AbstractC3309z0.b(context, j));
    }
}
