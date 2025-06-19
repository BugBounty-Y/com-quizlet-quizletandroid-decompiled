package kotlinx.coroutines.flow.internal;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;
import kotlinx.coroutines.flow.e0;

/* renamed from: kotlinx.coroutines.flow.internal.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4996d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ InterfaceC5002j l;
    public final /* synthetic */ AbstractC4998f m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4996d(InterfaceC5002j interfaceC5002j, AbstractC4998f abstractC4998f, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = interfaceC5002j;
        this.m = abstractC4998f;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4996d c4996d = new C4996d(this.l, this.m, hVar);
        c4996d.k = obj;
        return c4996d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4996d) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            kotlinx.coroutines.channels.w wVarJ = this.m.j((kotlinx.coroutines.C) this.k);
            this.j = 1;
            Object objO = e0.o(this.l, wVarJ, true, this);
            if (objO != obj2) {
                objO = Unit.a;
            }
            if (objO == obj2) {
                return obj2;
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
