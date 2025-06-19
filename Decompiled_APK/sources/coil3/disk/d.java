package coil3.disk;

import androidx.glance.appwidget.protobuf.Z;
import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import okio.AbstractC5085b;
import okio.C5089f;

/* loaded from: classes.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ e j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(e eVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        e eVar = this.j;
        synchronized (eVar.h) {
            if (!eVar.m || eVar.n) {
                return Unit.a;
            }
            try {
                eVar.B();
            } catch (IOException unused) {
                eVar.o = true;
            }
            try {
                if (eVar.j >= 2000) {
                    eVar.D();
                }
            } catch (IOException unused2) {
                eVar.p = true;
                eVar.k = AbstractC5085b.b(new C5089f());
            }
            return Unit.a;
        }
    }
}
