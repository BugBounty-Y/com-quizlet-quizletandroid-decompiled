package androidx.compose.ui;

import androidx.glance.appwidget.protobuf.Z;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ kotlin.jvm.internal.r l;
    public final /* synthetic */ AtomicReference m;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public t(Function1 function1, AtomicReference atomicReference, Function2 function2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = (kotlin.jvm.internal.r) function1;
        this.m = atomicReference;
        this.n = (kotlin.coroutines.jvm.internal.i) function2;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        t tVar = new t(this.l, this.m, this.n, hVar);
        tVar.k = obj;
        return tVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r7v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r9v9, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        s sVar;
        s sVar2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        AtomicReference atomicReference = this.m;
        try {
            if (i == 0) {
                Z.e(obj);
                C c = (C) this.k;
                sVar = new s(E.s(c.getCoroutineContext()), this.l.invoke(c));
                s sVar3 = (s) atomicReference.getAndSet(sVar);
                if (sVar3 != null) {
                    InterfaceC5025j0 interfaceC5025j0 = sVar3.a;
                    this.k = sVar;
                    this.j = 1;
                    if (E.k(interfaceC5025j0, this) != aVar) {
                    }
                    return aVar;
                }
            } else {
                if (i != 1) {
                    if (i != 2) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    sVar2 = (s) this.k;
                    try {
                        Z.e(obj);
                        while (!atomicReference.compareAndSet(sVar2, null) && atomicReference.get() == sVar2) {
                        }
                        return obj;
                    } catch (Throwable th) {
                        th = th;
                        while (!atomicReference.compareAndSet(sVar2, null)) {
                        }
                        throw th;
                    }
                }
                sVar = (s) this.k;
                Z.e(obj);
            }
            ?? r9 = this.n;
            Object obj2 = sVar.b;
            this.k = sVar;
            this.j = 2;
            obj = r9.invoke(obj2, this);
            if (obj != aVar) {
                sVar2 = sVar;
                while (!atomicReference.compareAndSet(sVar2, null)) {
                }
                return obj;
            }
            return aVar;
        } catch (Throwable th2) {
            th = th2;
            sVar2 = sVar;
            while (!atomicReference.compareAndSet(sVar2, null) && atomicReference.get() == sVar2) {
            }
            throw th;
        }
    }
}
