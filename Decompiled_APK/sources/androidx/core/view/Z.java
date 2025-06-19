package androidx.core.view;

import android.view.View;
import android.view.ViewGroup;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class Z extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public int k;
    public /* synthetic */ Object l;
    final /* synthetic */ View m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Z(View view, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = view;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        Z z = new Z(this.m, hVar);
        z.l = obj;
        return z;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((Z) create((kotlin.sequences.i) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            kotlin.sequences.i iVar = (kotlin.sequences.i) this.l;
            View view = this.m;
            this.l = iVar;
            this.k = 1;
            iVar.a(view, this);
            return aVar;
        }
        if (i == 1) {
            kotlin.sequences.i iVar2 = (kotlin.sequences.i) this.l;
            androidx.glance.appwidget.protobuf.Z.e(obj);
            View view2 = this.m;
            if (view2 instanceof ViewGroup) {
                this.l = null;
                this.k = 2;
                iVar2.getClass();
                Object objD = iVar2.d(new C(new Y((ViewGroup) view2)), this);
                if (objD != aVar) {
                    objD = Unit.a;
                }
                if (objD == aVar) {
                    return aVar;
                }
            }
        } else {
            if (i != 2) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
