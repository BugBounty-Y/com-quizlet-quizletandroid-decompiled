package com.quizlet.login.navigation;

import android.content.Context;
import android.content.Intent;
import androidx.core.app.W;
import com.google.android.gms.internal.mlkit_vision_document_scanner.B;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.infra.navigation.m;
import com.quizlet.login.LoginNavActivity;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements m {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.features.infra.navigation.m
    public final void j(Intent intent) {
        String str = LoginNavActivity.i;
        Context context = this.a;
        Intent intentB = AbstractC4178x.b(context, "context", context, LoginNavActivity.class);
        intentB.putExtra("navigationRoute", "login");
        if (intent == null) {
            context.startActivity(intentB);
            return;
        }
        W w = new W(context);
        w.a(intent);
        w.a.add(intentB);
        w.e();
    }

    @Override // com.quizlet.features.infra.navigation.m
    public final void r(Intent intent) {
        boolean z = intent != null;
        String str = LoginNavActivity.i;
        Context context = this.a;
        Intent intentC = B.c(context, z);
        if (intent == null) {
            context.startActivity(intentC);
            return;
        }
        W w = new W(context);
        w.a(intent);
        w.a.add(intentC);
        w.e();
    }

    @Override // com.quizlet.features.infra.navigation.m
    public final void x(String code) {
        Intrinsics.checkNotNullParameter(code, "code");
        String str = LoginNavActivity.i;
        Context context = this.a;
        context.startActivity(B.b(context, code));
    }
}
