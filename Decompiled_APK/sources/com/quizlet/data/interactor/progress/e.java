package com.quizlet.data.interactor.progress;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e {
    public final com.quizlet.remote.model.progress.e a;
    public final com.quizlet.data.repository.folderwithcreator.e b;

    public e(com.quizlet.remote.model.progress.e remoteRepository, com.quizlet.data.repository.folderwithcreator.e localRepository) {
        Intrinsics.checkNotNullParameter(remoteRepository, "remoteRepository");
        Intrinsics.checkNotNullParameter(localRepository, "localRepository");
        this.a = remoteRepository;
        this.b = localRepository;
    }
}
