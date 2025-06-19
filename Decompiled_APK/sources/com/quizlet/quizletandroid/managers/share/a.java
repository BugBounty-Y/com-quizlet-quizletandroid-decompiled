package com.quizlet.quizletandroid.managers.share;

import io.reactivex.rxjava3.functions.h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public static final a a = new a();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        Boolean canShareEmail = (Boolean) obj;
        Intrinsics.checkNotNullParameter(canShareEmail, "canShareEmail");
        return canShareEmail.booleanValue() ? com.quizlet.features.infra.basestudy.data.models.shareset.a.b : com.quizlet.features.infra.basestudy.data.models.shareset.a.d;
    }
}
