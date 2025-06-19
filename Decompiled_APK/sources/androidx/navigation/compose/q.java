package androidx.navigation.compose;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import androidx.navigation.C1291m;
import java.util.List;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ InterfaceC0773a0 j;
    public final /* synthetic */ s k;
    public final /* synthetic */ androidx.compose.runtime.snapshots.q l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(InterfaceC0773a0 interfaceC0773a0, s sVar, androidx.compose.runtime.snapshots.q qVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = interfaceC0773a0;
        this.k = sVar;
        this.l = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new q(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((q) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        for (C1291m c1291m : (Set) this.j.getValue()) {
            s sVar = this.k;
            if (!((List) ((s0) sVar.b().e.a).getValue()).contains(c1291m) && !this.l.contains(c1291m)) {
                sVar.b().c(c1291m);
            }
        }
        return Unit.a;
    }
}
