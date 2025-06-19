package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import com.quizlet.local.datastore.preferences.C4579o;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class D extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public InterfaceC5002j l;
    public final /* synthetic */ C4579o m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(C4579o c4579o, kotlin.coroutines.h hVar) {
        super(hVar);
        this.m = c4579o;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.m.emit(null, this);
    }
}
