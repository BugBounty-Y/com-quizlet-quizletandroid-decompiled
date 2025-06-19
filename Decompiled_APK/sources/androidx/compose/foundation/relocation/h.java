package androidx.compose.foundation.relocation;

import androidx.compose.foundation.C0473q;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.a0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ j k;
    public final /* synthetic */ C0473q l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(j jVar, C0473q c0473q, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = jVar;
        this.l = c0473q;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        a kVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            j jVar = this.k;
            if (jVar.m) {
                if (jVar.a.m) {
                    kVar = (a) AbstractC0910f.j(jVar, j.p);
                    if (kVar == null) {
                        kVar = new k(jVar);
                    }
                } else {
                    kVar = null;
                }
                if (kVar != null) {
                    a0 a0VarU = AbstractC0910f.u(jVar);
                    this.j = 1;
                    if (kVar.S(a0VarU, this.l, this) == aVar) {
                        return aVar;
                    }
                }
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
