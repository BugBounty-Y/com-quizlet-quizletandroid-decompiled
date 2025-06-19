package com.quizlet.quizletandroid.config;

import com.quizlet.data.interactor.achievements.f;
import com.quizlet.login.magiclink.ui.e;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes3.dex */
public final class b {
    public final f a;
    public final u b;

    public b(f deepLinkLoader) {
        Intrinsics.checkNotNullParameter(deepLinkLoader, "deepLinkLoader");
        this.a = deepLinkLoader;
        this.b = l.b(new e(this, 3));
    }
}
