package androidx.work.impl;

import androidx.glance.appwidget.protobuf.Z;
import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5027k0;

/* loaded from: classes.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ F k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(F f, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = f;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object wVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        F f = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                C5027k0 c5027k0 = f.n;
                B b = new B(f, null);
                this.j = 1;
                obj = kotlinx.coroutines.E.J(c5027k0, b, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            wVar = (z) obj;
        } catch (WorkerStoppedException e) {
            wVar = new y(e.a);
        } catch (CancellationException unused) {
            wVar = new w();
        } catch (Throwable th) {
            androidx.work.z.c().b(G.a, "Unexpected error in WorkerWrapper", th);
            wVar = new w();
        }
        Object objN = f.i.n(new A(0, wVar, f));
        Intrinsics.checkNotNullExpressionValue(objN, "workDatabase.runInTransa…          }\n            )");
        return objN;
    }
}
