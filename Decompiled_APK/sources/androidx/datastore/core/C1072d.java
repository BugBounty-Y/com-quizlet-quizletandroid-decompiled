package androidx.datastore.core;

import com.google.android.gms.internal.mlkit_vision_barcode.L6;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.datastore.core.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1072d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ List l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1072d(List list, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = list;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1072d c1072d = new C1072d(this.l, hVar);
        c1072d.k = obj;
        return c1072d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1072d) create((C1079k) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C1079k c1079k = (C1079k) this.k;
            this.j = 1;
            if (L6.a(this.l, c1079k, this) == aVar) {
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
