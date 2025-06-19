package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import java.util.ArrayList;
import java.util.List;

/* loaded from: classes3.dex */
public final class w extends kotlin.coroutines.jvm.internal.c {
    public List j;
    public List k;
    public ArrayList l;
    public ArrayList m;
    public /* synthetic */ Object n;
    public final /* synthetic */ G o;
    public int p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(G g, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.o = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.p |= Integer.MIN_VALUE;
        return G.B(this.o, null, null, null, this);
    }
}
