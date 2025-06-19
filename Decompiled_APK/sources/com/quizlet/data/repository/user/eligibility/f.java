package com.quizlet.data.repository.user.eligibility;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.generated.enums.I0;
import java.util.Map;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class f extends i implements Function2 {
    public int j;
    public final /* synthetic */ g k;
    public final /* synthetic */ Map l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(g gVar, Map map, h hVar) {
        super(2, hVar);
        this.k = gVar;
        this.l = map;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new f(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        g gVar = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                com.quizlet.data.interactor.achievements.f fVar = gVar.a;
                Map map = this.l;
                this.j = 1;
                for (Map.Entry entry : map.entrySet()) {
                    I0 i0 = (I0) entry.getKey();
                    Boolean bool = (Boolean) entry.getValue();
                    bool.getClass();
                    ((com.quizlet.local.cache.caches.b) fVar.b).a(i0, bool);
                }
                if (Unit.a == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
        } catch (Throwable th) {
            gVar.c.c("Failed to save feature eligibility to local storage", th);
        }
        return Unit.a;
    }
}
