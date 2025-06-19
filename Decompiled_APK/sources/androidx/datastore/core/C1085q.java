package androidx.datastore.core;

import com.google.android.gms.internal.mlkit_vision_barcode.Q6;
import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.datastore.core.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1085q extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public int k;
    public /* synthetic */ Object l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C1085q(int i, int i2, kotlin.coroutines.h hVar) {
        super(i, hVar);
        this.j = i2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.j) {
            case 0:
                return new C1085q((P) this.l, (kotlin.coroutines.h) obj3).invokeSuspend(Unit.a);
            case 1:
                ((Boolean) obj2).getClass();
                C1085q c1085q = new C1085q(3, 1, (kotlin.coroutines.h) obj3);
                c1085q.l = (d0) obj;
                return c1085q.invokeSuspend(Unit.a);
            default:
                C1085q c1085q2 = new C1085q(3, 2, (kotlin.coroutines.h) obj3);
                c1085q2.l = (InterfaceC5002j) obj;
                return c1085q2.invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                int i = this.k;
                if (i == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    this.k = 1;
                    if (P.b((P) this.l, this) == aVar) {
                        return aVar;
                    }
                } else {
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            case 1:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.k;
                if (i2 != 0) {
                    if (i2 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    return obj;
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
                d0 d0Var = (d0) this.l;
                this.k = 1;
                Object objE = d0Var.e(this);
                return objE == aVar2 ? aVar2 : objE;
            default:
                kotlin.coroutines.intrinsics.a aVar3 = kotlin.coroutines.intrinsics.a.a;
                int i3 = this.k;
                if (i3 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    InterfaceC5002j interfaceC5002j = (InterfaceC5002j) this.l;
                    androidx.datastore.preferences.core.b bVarA = Q6.a();
                    this.k = 1;
                    if (interfaceC5002j.emit(bVarA, this) == aVar3) {
                        return aVar3;
                    }
                } else {
                    if (i3 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1085q(P p, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.j = 0;
        this.l = p;
    }
}
