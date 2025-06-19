package androidx.work.impl;

import androidx.glance.appwidget.protobuf.Z;
import com.comscore.util.log.LogLevel;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.d {
    public int j;
    public /* synthetic */ Throwable k;
    public /* synthetic */ long l;

    @Override // kotlin.jvm.functions.d
    public final Object invoke(Object obj, Object obj2, Object obj3, Object obj4) {
        long jLongValue = ((Number) obj3).longValue();
        k kVar = new k(4, (kotlin.coroutines.h) obj4);
        kVar.k = (Throwable) obj2;
        kVar.l = jLongValue;
        return kVar.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            Throwable th = this.k;
            long j = this.l;
            androidx.work.z.c().b(m.a, "Cannot check for unfinished work", th);
            long jMin = Math.min(j * LogLevel.NONE, m.b);
            this.j = 1;
            if (kotlinx.coroutines.E.n(jMin, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Boolean.TRUE;
    }
}
