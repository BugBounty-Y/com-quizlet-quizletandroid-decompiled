package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.Intent;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.login.LoginNavActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class B {
    public static Intent a(Context context) {
        Intent intentB = AbstractC4178x.b(context, "context", context, LoginNavActivity.class);
        intentB.putExtra("navigationRoute", "intro");
        intentB.setAction("open_start_activity");
        return intentB;
    }

    public static Intent b(Context context, String magicLinkCode) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(magicLinkCode, "magicLinkCode");
        Intent intent = new Intent(context, (Class<?>) LoginNavActivity.class);
        intent.putExtra("magicLinkCode", magicLinkCode);
        intent.setFlags(335544320);
        intent.setAction("open_start_activity");
        return intent;
    }

    public static Intent c(Context context, boolean z) {
        Intent intentB = AbstractC4178x.b(context, "context", context, LoginNavActivity.class);
        intentB.putExtra("navigationRoute", "signup");
        intentB.putExtra("shouldSkipUpsell", z);
        return intentB;
    }
}
