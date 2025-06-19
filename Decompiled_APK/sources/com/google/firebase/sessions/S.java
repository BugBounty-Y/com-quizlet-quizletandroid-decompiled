package com.google.firebase.sessions;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class S extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public B j;
    public U k;
    public P l;
    public com.google.firebase.h m;
    public N n;
    public com.google.firebase.sessions.settings.j o;
    public int p;
    public final /* synthetic */ U q;
    public final /* synthetic */ N r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S(U u, N n, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.q = u;
        this.r = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new S(this.q, this.r, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((S) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x00c5  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x00de  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00e0  */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r18) {
        /*
            Method dump skipped, instructions count: 280
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.sessions.S.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
