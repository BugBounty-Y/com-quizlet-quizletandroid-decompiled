package com.quizlet.explanations.navigation;

import android.content.Context;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import com.quizlet.explanations.textbook.ui.TextbookActivity;
import com.quizlet.features.infra.navigation.z;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.internal.platform.m;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class c implements z {
    public final Context a;

    public c(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.z
    public final void A(String id) {
        Intrinsics.checkNotNullParameter(id, "mediaExerciseId");
        Intrinsics.checkNotNullParameter(id, "id");
        TextbookSetUpState.Exercise exercise = new TextbookSetUpState.Exercise(id);
        String str = TextbookActivity.r;
        Context context = this.a;
        context.startActivity(m.c(context, exercise));
    }

    @Override // com.quizlet.features.infra.navigation.z
    public final void l(String isbn) {
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        Intrinsics.checkNotNullParameter(isbn, "isbn");
        TextbookSetUpState.TableOfContents tableOfContents = new TextbookSetUpState.TableOfContents(isbn);
        String str = TextbookActivity.r;
        Context context = this.a;
        context.startActivity(m.c(context, tableOfContents));
    }
}
