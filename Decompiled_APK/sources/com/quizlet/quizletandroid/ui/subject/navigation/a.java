package com.quizlet.quizletandroid.ui.subject.navigation;

import android.content.Context;
import android.content.Intent;
import androidx.activity.result.b;
import com.quizlet.features.infra.navigation.y;
import com.quizlet.generated.enums.I1;
import com.quizlet.quizletandroid.ui.subject.SubjectCategoryActivity;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements y {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.y
    public final void B(b launcher, I1 subjectCategoryType) {
        Intrinsics.checkNotNullParameter(launcher, "launcher");
        Intrinsics.checkNotNullParameter(subjectCategoryType, "subjectCategoryType");
        String str = SubjectCategoryActivity.k;
        Context context = this.a;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(subjectCategoryType, "subjectCategoryType");
        Intent intent = new Intent(context, (Class<?>) SubjectCategoryActivity.class);
        intent.putExtra("subject_category_type", subjectCategoryType.a());
        intent.putExtra("subject_type", (String) null);
        launcher.a(intent);
    }
}
