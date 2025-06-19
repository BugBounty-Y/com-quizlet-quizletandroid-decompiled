package androidx.compose.material;

import androidx.compose.material3.internal.C0641e;
import kotlin.Unit;

/* renamed from: androidx.compose.material.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0559b extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public /* synthetic */ kotlinx.coroutines.C k;
    public /* synthetic */ float l;
    public final /* synthetic */ Object m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0559b(Object obj, kotlin.coroutines.h hVar, int i) {
        super(3, hVar);
        this.j = i;
        this.m = obj;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        int i = this.j;
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) obj;
        float fFloatValue = ((Number) obj2).floatValue();
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj3;
        switch (i) {
            case 0:
                C0559b c0559b = new C0559b((C0575s) this.m, hVar, 0);
                c0559b.k = c;
                c0559b.l = fFloatValue;
                return c0559b.invokeSuspend(Unit.a);
            default:
                C0559b c0559b2 = new C0559b((androidx.work.impl.model.t) this.m, hVar, 1);
                c0559b2.k = c;
                c0559b2.l = fFloatValue;
                return c0559b2.invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = this.m;
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                kotlinx.coroutines.E.A(this.k, null, null, new C0558a((C0575s) obj2, this.l, null), 3);
                break;
            default:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                kotlinx.coroutines.E.A(this.k, null, null, new C0641e((androidx.work.impl.model.t) obj2, this.l, null), 3);
                break;
        }
        return Unit.a;
    }
}
