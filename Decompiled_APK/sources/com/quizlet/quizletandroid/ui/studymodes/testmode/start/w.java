package com.quizlet.quizletandroid.ui.studymodes.testmode.start;

import com.quizlet.features.infra.studysetting.data.TestStudyModeConfig;

/* loaded from: classes3.dex */
public final class w extends kotlin.coroutines.jvm.internal.c {
    public A j;
    public i k;
    public TestStudyModeConfig l;
    public String m;
    public boolean n;
    public boolean o;
    public boolean p;
    public /* synthetic */ Object q;
    public final /* synthetic */ A r;
    public int s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(A a, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.r = a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.q = obj;
        this.s |= Integer.MIN_VALUE;
        return A.A(this.r, null, this);
    }
}
