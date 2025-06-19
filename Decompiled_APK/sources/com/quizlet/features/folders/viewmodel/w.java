package com.quizlet.features.folders.viewmodel;

import java.util.ArrayList;

/* loaded from: classes3.dex */
public final class w extends kotlin.coroutines.jvm.internal.c {
    public Object j;
    public N k;
    public ArrayList l;
    public boolean m;
    public boolean n;
    public /* synthetic */ Object o;
    public final /* synthetic */ x p;
    public int q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(x xVar, kotlin.coroutines.h hVar) {
        super(hVar);
        this.p = xVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.o = obj;
        this.q |= Integer.MIN_VALUE;
        return this.p.emit(new kotlin.r(null), this);
    }
}
