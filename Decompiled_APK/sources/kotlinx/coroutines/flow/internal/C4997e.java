package kotlinx.coroutines.flow.internal;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: kotlinx.coroutines.flow.internal.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4997e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ AbstractC4998f l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4997e(AbstractC4998f abstractC4998f, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = abstractC4998f;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4997e c4997e = new C4997e(this.l, hVar);
        c4997e.k = obj;
        return c4997e;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4997e) create((kotlinx.coroutines.channels.u) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            kotlinx.coroutines.channels.u uVar = (kotlinx.coroutines.channels.u) this.k;
            this.j = 1;
            if (this.l.e(uVar, this) == aVar) {
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
