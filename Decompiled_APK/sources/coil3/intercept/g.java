package coil3.intercept;

import android.content.Context;
import androidx.camera.core.a0;
import androidx.glance.appwidget.protobuf.Z;
import coil3.request.m;
import coil3.request.o;
import coil3.u;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3473j;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ h k;
    public final /* synthetic */ coil3.request.g l;
    public final /* synthetic */ Object m;
    public final /* synthetic */ m n;
    public final /* synthetic */ coil3.f o;
    public final /* synthetic */ coil3.memory.a p;
    public final /* synthetic */ a0 q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(h hVar, coil3.request.g gVar, Object obj, m mVar, coil3.f fVar, coil3.memory.a aVar, a0 a0Var, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
        this.l = gVar;
        this.m = obj;
        this.n = mVar;
        this.o = fVar;
        this.p = aVar;
        this.q = a0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.k, this.l, this.m, this.n, this.o, this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object objB;
        boolean z;
        coil3.memory.c cVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            h hVar = this.k;
            coil3.request.g gVar = this.l;
            Object obj2 = this.m;
            m mVar = this.n;
            coil3.f fVar = this.o;
            this.j = 1;
            objB = h.b(hVar, gVar, obj2, mVar, fVar, this);
            if (objB == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objB = obj;
        }
        a aVar2 = (a) objB;
        coil3.util.a aVar3 = this.k.b;
        synchronized (aVar3) {
            try {
                u uVar = (u) aVar3.a.get();
                if (uVar == null) {
                    aVar3.a();
                } else if (aVar3.b == null) {
                    Context context = uVar.a.a;
                    aVar3.b = context;
                    context.registerComponentCallbacks(aVar3);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        com.google.android.gms.internal.instantapps.a aVar4 = this.k.d;
        coil3.memory.a aVar5 = this.p;
        coil3.request.g gVar2 = this.l;
        if (aVar5 == null || !gVar2.i.b || !aVar2.a.c() || (cVar = (coil3.memory.c) ((u) aVar4.b).a.c.getValue()) == null) {
            z = false;
        } else {
            LinkedHashMap linkedHashMap = new LinkedHashMap();
            linkedHashMap.put("coil#is_sampled", Boolean.valueOf(aVar2.b));
            String str = aVar2.d;
            if (str != null) {
                linkedHashMap.put("coil#disk_cache_key", str);
            }
            coil3.j jVar = aVar2.a;
            Map mapC = AbstractC3473j.c(linkedHashMap);
            synchronized (cVar.c) {
                long jA = jVar.a();
                if (jA < 0) {
                    throw new IllegalStateException(("Image size must be non-negative: " + jA).toString());
                }
                cVar.a.k(aVar5, jVar, mapC, jA);
                Unit unit = Unit.a;
            }
            z = true;
        }
        coil3.j jVar2 = aVar2.a;
        coil3.request.g gVar3 = this.l;
        coil3.decode.h hVar2 = aVar2.c;
        coil3.memory.a aVar6 = this.p;
        if (!z) {
            aVar6 = null;
        }
        coil3.memory.a aVar7 = aVar6;
        String str2 = aVar2.d;
        boolean z2 = aVar2.b;
        a0 a0Var = this.q;
        return new o(jVar2, gVar3, hVar2, aVar7, str2, z2, a0Var != null && a0Var.b);
    }
}
