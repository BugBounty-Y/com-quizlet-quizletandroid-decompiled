package androidx.work;

import androidx.glance.appwidget.protobuf.Z;
import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.work.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1445t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i l;
    public final /* synthetic */ androidx.concurrent.futures.i m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C1445t(Function2 function2, androidx.concurrent.futures.i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = (kotlin.coroutines.jvm.internal.i) function2;
        this.m = iVar;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1445t c1445t = new C1445t(this.l, this.m, hVar);
        c1445t.k = obj;
        return c1445t;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1445t) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        androidx.concurrent.futures.i iVar = this.m;
        try {
            if (i == 0) {
                Z.e(obj);
                kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
                ?? r1 = this.l;
                this.j = 1;
                obj = r1.invoke(c, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            iVar.b(obj);
        } catch (CancellationException unused) {
            iVar.c();
        } catch (Throwable th) {
            iVar.d(th);
        }
        return Unit.a;
    }
}
