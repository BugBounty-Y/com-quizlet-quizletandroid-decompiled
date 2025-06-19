package com.quizlet.quizletandroid.ui.startpage.nav2;

import java.util.List;

/* loaded from: classes3.dex */
public final class G extends kotlin.coroutines.jvm.internal.c {
    public Y j;
    public List k;
    public /* synthetic */ Object l;
    public final /* synthetic */ Y m;
    public int n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(Y y, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.m = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.l = obj;
        this.n |= Integer.MIN_VALUE;
        return this.m.I(this);
    }
}
