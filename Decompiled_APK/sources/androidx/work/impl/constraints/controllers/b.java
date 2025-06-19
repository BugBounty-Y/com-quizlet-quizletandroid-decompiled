package androidx.work.impl.constraints.controllers;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.z;
import com.google.android.gms.internal.mlkit_vision_camera.F1;
import java.util.LinkedHashSet;
import java.util.Objects;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.channels.u;

/* loaded from: classes.dex */
public final class b extends i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ c l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, h hVar) {
        super(2, hVar);
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        b bVar = new b(this.l, hVar);
        bVar.k = obj;
        return bVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((u) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            u uVar = (u) this.k;
            c cVar = this.l;
            a listener = new a(cVar, uVar);
            androidx.work.impl.constraints.trackers.e eVar = cVar.a;
            eVar.getClass();
            Intrinsics.checkNotNullParameter(listener, "listener");
            synchronized (eVar.c) {
                try {
                    if (((LinkedHashSet) eVar.e).add(listener)) {
                        if (((LinkedHashSet) eVar.e).size() == 1) {
                            eVar.d = eVar.c();
                            z zVarC = z.c();
                            int i2 = androidx.work.impl.constraints.trackers.f.a;
                            Objects.toString(eVar.d);
                            zVarC.getClass();
                            eVar.e();
                        }
                        listener.a(eVar.d);
                    }
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    throw th;
                }
            }
            androidx.credentials.playservices.controllers.BeginSignIn.d dVar = new androidx.credentials.playservices.controllers.BeginSignIn.d(12, this.l, listener);
            this.j = 1;
            if (F1.a(uVar, dVar, this) == aVar) {
                return aVar;
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
