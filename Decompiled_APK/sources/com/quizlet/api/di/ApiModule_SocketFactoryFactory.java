package com.quizlet.api.di;

import com.quizlet.api.util.TaggedSocketFactory;
import dagger.internal.c;
import javax.net.SocketFactory;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class ApiModule_SocketFactoryFactory implements c {
    private final ApiModule module;

    @Override // javax.inject.a
    public SocketFactory get() {
        this.module.getClass();
        SocketFactory socketFactory = SocketFactory.getDefault();
        Intrinsics.checkNotNullExpressionValue(socketFactory, "getDefault(...)");
        return new TaggedSocketFactory(socketFactory);
    }
}
