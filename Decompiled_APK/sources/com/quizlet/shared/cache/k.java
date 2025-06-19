package com.quizlet.shared.cache;

import com.google.android.gms.internal.mlkit_vision_barcode.Q4;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return Q4.e(null, this);
    }
}
