package androidx.compose.material;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3236q0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0572o extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ C0575s k;
    public final /* synthetic */ Object l;
    public final /* synthetic */ C0560c m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0572o(C0575s c0575s, Object obj, C0560c c0560c, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = c0575s;
        this.l = obj;
        this.m = c0560c;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C0572o(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C0572o) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            Object obj2 = this.l;
            C0575s c0575s = this.k;
            c0575s.i(obj2);
            C0567j c0567j = new C0567j(c0575s, 1);
            C0571n c0571n = new C0571n(this.m, c0575s, null);
            this.j = 1;
            if (AbstractC3236q0.b(c0567j, c0571n, this) == aVar) {
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
