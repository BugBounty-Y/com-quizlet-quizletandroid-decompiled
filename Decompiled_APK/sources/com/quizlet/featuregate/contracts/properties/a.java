package com.quizlet.featuregate.contracts.properties;

import androidx.camera.core.AbstractC0151c;

/* loaded from: classes2.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return AbstractC0151c.a(null, this);
    }
}
