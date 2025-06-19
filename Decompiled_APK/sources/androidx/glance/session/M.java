package androidx.glance.session;

import androidx.camera.camera2.internal.s0;
import androidx.glance.appwidget.protobuf.Z;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class M extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ x l;
    public final /* synthetic */ s0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public M(x xVar, s0 s0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = xVar;
        this.m = s0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        M m = new M(this.l, this.m, hVar);
        m.k = obj;
        return m;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((M) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        AtomicReference atomicReference;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
            AtomicReference atomicReference2 = new AtomicReference(null);
            L l = new L(this.l, this.m, c, atomicReference2, null);
            this.k = atomicReference2;
            this.j = 1;
            obj = kotlinx.coroutines.E.m(l, this);
            if (obj == aVar) {
                return aVar;
            }
            atomicReference = atomicReference2;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            atomicReference = (AtomicReference) this.k;
            Z.e(obj);
        }
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) atomicReference.get();
        if (interfaceC5025j0 != null) {
            interfaceC5025j0.j(null);
        }
        return obj;
    }
}
