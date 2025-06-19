package com.quizlet.quizletandroid.config;

import com.quizlet.data.interactor.achievements.f;
import com.quizlet.login.magiclink.ui.e;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes3.dex */
public final class a {
    public final u a;

    public a(f deepLinkLoader) {
        Intrinsics.checkNotNullParameter(deepLinkLoader, "deepLinkLoader");
        this.a = l.b(new e(deepLinkLoader, 2));
    }
}
