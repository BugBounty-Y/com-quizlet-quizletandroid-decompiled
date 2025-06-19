package com.mayakapps.kache;

import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.mayakapps.kache.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4035d implements InterfaceC4032a {
    public final H a;

    public C4035d(H baseKache, kotlinx.coroutines.internal.d creationScope) {
        Intrinsics.checkNotNullParameter(baseKache, "baseKache");
        Intrinsics.checkNotNullParameter(creationScope, "creationScope");
        this.a = baseKache;
    }

    @Override // com.mayakapps.kache.InterfaceC4032a
    public final Object a(kotlin.coroutines.h hVar) {
        Object objA = this.a.a(hVar);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : Unit.a;
    }

    @Override // com.mayakapps.kache.InterfaceC4032a
    public final Object b(com.quizlet.shared.cache.k kVar) {
        return this.a.d.d(kVar);
    }

    @Override // com.mayakapps.kache.InterfaceC4032a
    public final Object c(String str, kotlin.coroutines.h hVar) {
        Object objC = this.a.c(str, hVar);
        return objC == kotlin.coroutines.intrinsics.a.a ? objC : Unit.a;
    }
}
