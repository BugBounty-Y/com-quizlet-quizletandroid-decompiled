package com.quizlet.data.interactor.folderstudymaterial;

import com.google.android.gms.internal.mlkit_vision_document_scanner.B6;

/* loaded from: classes2.dex */
public final class q extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        Object objA = B6.a(null, null, 0L, this);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : new kotlin.r(objA);
    }
}
