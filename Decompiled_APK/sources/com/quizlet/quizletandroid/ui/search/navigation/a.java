package com.quizlet.quizletandroid.ui.search.navigation;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_document_scanner.N5;
import com.quizlet.features.infra.navigation.u;
import com.quizlet.quizletandroid.ui.search.SearchActivity;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements u {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.u
    public final void b(String str) {
        String str2 = SearchActivity.q;
        Context context = this.a;
        context.startActivity(N5.d(context, str));
    }
}
