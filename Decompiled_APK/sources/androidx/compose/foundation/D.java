package androidx.compose.foundation;

import androidx.compose.foundation.gestures.C0326g0;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class D extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public int k;
    public /* synthetic */ C0326g0 l;
    public /* synthetic */ long m;
    public final /* synthetic */ AbstractC0368j n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ D(AbstractC0368j abstractC0368j, kotlin.coroutines.h hVar, int i) {
        super(3, hVar);
        this.j = i;
        this.n = abstractC0368j;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        C0326g0 c0326g0 = (C0326g0) obj;
        androidx.compose.ui.geometry.b bVar = (androidx.compose.ui.geometry.b) obj2;
        switch (this.j) {
            case 0:
                long j = bVar.a;
                D d = new D((E) this.n, (kotlin.coroutines.h) obj3, 0);
                d.l = c0326g0;
                d.m = j;
                return d.invokeSuspend(Unit.a);
            default:
                long j2 = bVar.a;
                D d2 = new D((J) this.n, (kotlin.coroutines.h) obj3, 1);
                d2.l = c0326g0;
                d2.m = j2;
                return d2.invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objM;
        Object objM2;
        switch (this.j) {
            case 0:
                Object obj2 = kotlin.coroutines.intrinsics.a.a;
                int i = this.k;
                if (i == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    C0326g0 c0326g0 = this.l;
                    long j = this.m;
                    E e = (E) this.n;
                    if (e.t) {
                        this.k = 1;
                        androidx.compose.foundation.interaction.l lVar = e.p;
                        if (lVar == null || (objM = kotlinx.coroutines.E.m(new C0305d(c0326g0, j, lVar, e, null), this)) != obj2) {
                            objM = Unit.a;
                        }
                        if (objM == obj2) {
                            return obj2;
                        }
                    }
                } else {
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            default:
                Object obj3 = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.k;
                if (i2 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    C0326g0 c0326g02 = this.l;
                    long j2 = this.m;
                    J j3 = (J) this.n;
                    if (j3.t) {
                        this.k = 1;
                        androidx.compose.foundation.interaction.l lVar2 = j3.p;
                        if (lVar2 == null || (objM2 = kotlinx.coroutines.E.m(new C0305d(c0326g02, j2, lVar2, j3, null), this)) != obj3) {
                            objM2 = Unit.a;
                        }
                        if (objM2 == obj3) {
                            return obj3;
                        }
                    }
                } else {
                    if (i2 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
        }
    }
}
