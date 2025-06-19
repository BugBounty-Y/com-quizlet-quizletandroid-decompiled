package com.quizlet.features.flashcards.helpers;

import androidx.datastore.core.C1086s;
import kotlin.coroutines.h;

/* loaded from: classes2.dex */
public final class c extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public final /* synthetic */ C1086s l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(C1086s c1086s, h hVar) {
        super(hVar);
        this.l = c1086s;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.l.emit(null, this);
    }
}
