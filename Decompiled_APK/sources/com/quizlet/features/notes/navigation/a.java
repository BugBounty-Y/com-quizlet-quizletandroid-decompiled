package com.quizlet.features.notes.navigation;

import android.content.Context;
import com.quizlet.features.infra.navigation.x;
import com.quizlet.features.notes.detail.MagicNotesDetailActivity;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements x {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.x
    public final void n(String uuid) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        int i = MagicNotesDetailActivity.i;
        Context context = this.a;
        context.startActivity(assistantMode.utils.studiableMetadata.b.J(context, uuid, false, null));
    }
}
