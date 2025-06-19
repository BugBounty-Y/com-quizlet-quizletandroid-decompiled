package com.quizlet.data.interactor.folderstudymaterial;

import com.google.android.gms.internal.mlkit_vision_document_scanner.B6;

/* loaded from: classes2.dex */
public final class r extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        Object objB = B6.b(null, null, 0L, this);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : new kotlin.r(objB);
    }
}
