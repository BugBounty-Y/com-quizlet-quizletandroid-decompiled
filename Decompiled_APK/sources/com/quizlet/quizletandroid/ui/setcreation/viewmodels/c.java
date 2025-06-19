package com.quizlet.quizletandroid.ui.setcreation.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements io.reactivex.rxjava3.functions.b {
    public static final c a = new c();

    @Override // io.reactivex.rxjava3.functions.b
    public final Object apply(Object obj, Object obj2) {
        Boolean isUserUnderAged = (Boolean) obj;
        Boolean hasSeen = (Boolean) obj2;
        Intrinsics.checkNotNullParameter(isUserUnderAged, "isUserUnderAged");
        Intrinsics.checkNotNullParameter(hasSeen, "hasSeen");
        return Boolean.valueOf(isUserUnderAged.booleanValue() && !hasSeen.booleanValue());
    }
}
