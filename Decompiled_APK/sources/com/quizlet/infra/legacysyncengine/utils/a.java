package com.quizlet.infra.legacysyncengine.utils;

import timber.log.c;

/* loaded from: classes3.dex */
public final class a extends b {
    @Override // com.quizlet.infra.legacysyncengine.utils.b, io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        c.a(th);
        super.onError(th);
    }
}
