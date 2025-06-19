package com.quizlet.remote.model.login.magiclink;

import com.quizlet.remote.service.E;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class b {
    public final E a;
    public final AbstractC5040y b;

    public b(E service, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = service;
        this.b = ioDispatcher;
    }
}
