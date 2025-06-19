package com.braze.communication.dust;

import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.C;
import kotlinx.coroutines.channels.w;

/* loaded from: classes.dex */
public final class a extends kotlin.coroutines.jvm.internal.c {
    public h a;
    public C b;
    public w c;
    public Function1 d;
    public J e;
    public J f;
    public /* synthetic */ Object g;
    public final /* synthetic */ h h;
    public int i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(h hVar, kotlin.coroutines.jvm.internal.c cVar) {
        super(cVar);
        this.h = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.g = obj;
        this.i |= Integer.MIN_VALUE;
        return this.h.a(null, null, null, this);
    }
}
