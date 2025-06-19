package com.quizlet.quizletandroid.ui.startpage.nav2;

import com.google.android.gms.internal.ads.C3;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4695d extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public final /* synthetic */ C3 k;
    public int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4695d(C3 c3, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.k = c3;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.l |= Integer.MIN_VALUE;
        return this.k.b(this);
    }
}
