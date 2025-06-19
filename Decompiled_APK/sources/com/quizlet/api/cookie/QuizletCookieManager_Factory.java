package com.quizlet.api.cookie;

import com.quizlet.infra.contracts.api.a;
import dagger.internal.c;

/* loaded from: classes2.dex */
public final class QuizletCookieManager_Factory implements c {
    private final c qltjReceiverProvider;

    @Override // javax.inject.a
    public QuizletCookieManager get() {
        return new QuizletCookieManager((a) this.qltjReceiverProvider.get());
    }
}
