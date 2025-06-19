package com.quizlet.login;

import android.os.Bundle;
import androidx.activity.compose.j;
import androidx.activity.v;
import androidx.compose.runtime.internal.d;
import com.quizlet.features.achievements.ui.e;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class LoginNavActivity extends e {
    public static final String i;

    static {
        String name = LoginNavActivity.class.getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        i = name;
    }

    public LoginNavActivity() {
        super(4);
    }

    @Override // com.quizlet.features.achievements.ui.e, com.quizlet.baseui.base.c, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        j.a(this, new d(true, 819996514, new a(this, 1)));
    }

    @Override // com.quizlet.baseui.base.c
    public final String y() {
        return i;
    }
}
