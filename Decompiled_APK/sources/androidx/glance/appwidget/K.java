package androidx.glance.appwidget;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class K extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C1162c l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(C1162c c1162c, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c1162c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        K k = new K(this.l, hVar);
        k.k = obj;
        return k;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((K) create((androidx.glance.session.o) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.glance.session.o oVar = (androidx.glance.session.o) this.k;
            String strE = AbstractC3225o7.e(this.l.a);
            this.j = 1;
            C1182m c1182m = (C1182m) oVar.a.remove(strE);
            if (c1182m != null) {
                c1182m.c.i(null);
                c1182m.b.set(false);
                c1182m.l.j(null);
            }
            if (Unit.a == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
