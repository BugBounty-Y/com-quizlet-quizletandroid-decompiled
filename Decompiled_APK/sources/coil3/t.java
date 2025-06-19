package coil3;

import androidx.camera.core.a0;
import androidx.glance.appwidget.protobuf.Z;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ coil3.request.g k;
    public final /* synthetic */ u l;
    public final /* synthetic */ coil3.size.h m;
    public final /* synthetic */ f n;
    public final /* synthetic */ j o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(coil3.request.g gVar, u uVar, coil3.size.h hVar, f fVar, j jVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = gVar;
        this.l = uVar;
        this.m = hVar;
        this.n = fVar;
        this.o = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new t(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        List list = this.l.c.a;
        boolean z = this.o != null;
        coil3.request.g gVar = this.k;
        a0 a0Var = new a0(gVar, list, 0, gVar, this.m, this.n, z);
        this.j = 1;
        Object objF = a0Var.f(this);
        return objF == aVar ? aVar : objF;
    }
}
