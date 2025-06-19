package androidx.compose.foundation.text.selection;

import androidx.compose.foundation.gestures.k1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class Q extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ androidx.camera.lifecycle.f m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Q(androidx.camera.lifecycle.f fVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        Q q = new Q(this.m, hVar);
        q.l = obj;
        return q;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Q) create((androidx.compose.ui.input.pointer.z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.compose.ui.input.pointer.z zVar = (androidx.compose.ui.input.pointer.z) this.l;
            this.k = 1;
            obj = k1.e(zVar, androidx.compose.ui.input.pointer.g.b, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        if (((androidx.compose.ui.input.pointer.n) obj) != null) {
            ((C0540v) this.m.b).invoke();
            Unit unit = Unit.a;
        }
        return Unit.a;
    }
}
