package com.quizlet.quizletandroid.ui.common.ads;

import androidx.compose.animation.C0297y;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class s extends kotlin.coroutines.jvm.internal.c {
    public /* synthetic */ Object j;
    public int k;
    public final /* synthetic */ C0297y l;
    public InterfaceC5002j m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(C0297y c0297y, kotlin.coroutines.h hVar) {
        super(hVar);
        this.l = c0297y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.j = obj;
        this.k |= Integer.MIN_VALUE;
        return this.l.emit(null, this);
    }
}
