package com.quizlet.quizletandroid.ui.classcreation.navigation;

import android.content.Context;
import android.content.Intent;
import com.quizlet.features.infra.navigation.InterfaceC4344d;
import com.quizlet.quizletandroid.ui.classcreation.ClassCreationActivity;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements InterfaceC4344d {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.InterfaceC4344d
    public final void s() {
        int i = ClassCreationActivity.j;
        Context context = this.a;
        Intrinsics.checkNotNullParameter(context, "context");
        context.startActivity(new Intent(context, (Class<?>) ClassCreationActivity.class));
    }
}
