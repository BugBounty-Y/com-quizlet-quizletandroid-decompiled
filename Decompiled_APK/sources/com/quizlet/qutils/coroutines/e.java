package com.quizlet.qutils.coroutines;

import kotlin.r;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        Object objB = com.facebook.appevents.internal.d.b(null, this);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : new r(objB);
    }
}
