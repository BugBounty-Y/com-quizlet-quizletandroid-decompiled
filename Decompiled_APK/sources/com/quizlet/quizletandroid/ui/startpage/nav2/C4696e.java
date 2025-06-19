package com.quizlet.quizletandroid.ui.startpage.nav2;

import com.google.android.gms.internal.ads.C3;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4696e extends kotlin.coroutines.jvm.internal.c {
    public C3 j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C3 l;
    public int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4696e(C3 c3, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.l = c3;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.m |= Integer.MIN_VALUE;
        return this.l.c(this);
    }
}
