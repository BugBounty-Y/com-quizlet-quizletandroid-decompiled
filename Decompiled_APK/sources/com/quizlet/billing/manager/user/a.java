package com.quizlet.billing.manager.user;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3714r6;
import com.quizlet.db.data.models.wrappers.LoggedInUserStatus;
import io.reactivex.rxjava3.functions.h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements h {
    public static final a a = new a();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        LoggedInUserStatus it2 = (LoggedInUserStatus) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return AbstractC3714r6.b(it2.getCurrentUser());
    }
}
