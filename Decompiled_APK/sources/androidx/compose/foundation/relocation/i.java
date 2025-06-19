package androidx.compose.foundation.relocation;

import androidx.compose.foundation.C0473q;
import androidx.compose.ui.node.a0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.r;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ j k;
    public final /* synthetic */ a0 l;
    public final /* synthetic */ r m;
    public final /* synthetic */ C0473q n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public i(j jVar, a0 a0Var, Function0 function0, C0473q c0473q, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = jVar;
        this.l = a0Var;
        this.m = (r) function0;
        this.n = c0473q;
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        ?? r3 = this.m;
        C0473q c0473q = this.n;
        i iVar = new i(this.k, this.l, r3, c0473q, hVar);
        iVar.j = obj;
        return iVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        C c = (C) this.j;
        a0 a0Var = this.l;
        ?? r2 = this.m;
        j jVar = this.k;
        E.A(c, null, null, new g(jVar, a0Var, r2, null), 3);
        return E.A(c, null, null, new h(jVar, this.n, null), 3);
    }
}
