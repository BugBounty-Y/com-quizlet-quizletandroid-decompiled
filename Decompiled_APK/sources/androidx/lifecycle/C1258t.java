package androidx.lifecycle;

import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.lifecycle.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1258t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Y l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1258t(Y y, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = y;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1258t c1258t = new C1258t(this.l, hVar);
        c1258t.k = obj;
        return c1258t;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws Throwable {
        ((C1258t) create((kotlinx.coroutines.channels.u) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v0, types: [int] */
    /* JADX WARN: Type inference failed for: r2v1 */
    /* JADX WARN: Type inference failed for: r2v2, types: [androidx.lifecycle.Z] */
    /* JADX WARN: Type inference failed for: r2v4, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v7 */
    /* JADX WARN: Type inference failed for: r2v8 */
    /* JADX WARN: Type inference failed for: r2v9 */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        ?? r2 = this.j;
        Y y = this.l;
        try {
        } catch (Throwable th) {
            th = th;
        }
        if (r2 == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.camera.camera2.internal.D d = new androidx.camera.camera2.internal.D((kotlinx.coroutines.channels.u) this.k, 2);
            kotlinx.coroutines.scheduling.e eVar = kotlinx.coroutines.O.a;
            kotlinx.coroutines.android.d dVar = kotlinx.coroutines.internal.m.a.e;
            r rVar = new r(y, d, null);
            this.k = d;
            this.j = 1;
            r2 = d;
            if (kotlinx.coroutines.E.J(dVar, rVar, this) == aVar) {
                return aVar;
            }
        } else {
            if (r2 != 1) {
                if (r2 != 2) {
                    if (r2 != 3) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Throwable th2 = (Throwable) this.k;
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    throw th2;
                }
                Z z = (Z) this.k;
                try {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    throw new KotlinNothingValueException();
                } catch (Throwable th3) {
                    th = th3;
                    r2 = z;
                    Throwable th4 = th;
                    kotlinx.coroutines.scheduling.e eVar2 = kotlinx.coroutines.O.a;
                    CoroutineContext coroutineContextPlus = kotlinx.coroutines.internal.m.a.e.plus(kotlinx.coroutines.u0.a);
                    C1257s c1257s = new C1257s(y, r2, null);
                    this.k = th4;
                    this.j = 3;
                    if (kotlinx.coroutines.E.J(coroutineContextPlus, c1257s, this) == aVar) {
                        return aVar;
                    }
                    throw th4;
                }
            }
            Z z2 = (Z) this.k;
            androidx.glance.appwidget.protobuf.Z.e(obj);
            r2 = z2;
        }
        this.k = r2;
        this.j = 2;
        kotlinx.coroutines.E.g(this);
        return aVar;
    }
}
