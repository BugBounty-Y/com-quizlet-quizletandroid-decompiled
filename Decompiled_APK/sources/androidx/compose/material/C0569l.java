package androidx.compose.material;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3236q0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0569l extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ C0575s k;
    public final /* synthetic */ C0574q l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0569l(C0574q c0574q, C0575s c0575s, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = c0575s;
        this.l = c0574q;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C0569l(this.l, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C0569l) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0575s c0575s = this.k;
            C0567j c0567j = new C0567j(c0575s, 0);
            C0568k c0568k = new C0568k(this.l, c0575s, null);
            this.j = 1;
            if (AbstractC3236q0.b(c0567j, c0568k, this) == aVar) {
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
