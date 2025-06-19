package androidx.compose.material3;

import androidx.compose.foundation.gestures.AbstractC0349s0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.v3, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0746v3 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0752w3 k;
    public final /* synthetic */ int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0746v3(C0752w3 c0752w3, int i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0752w3;
        this.l = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0746v3(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0746v3) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.compose.foundation.N0 n0 = this.k.a;
            androidx.compose.animation.core.K0 k0 = AbstractC0765y4.b;
            this.j = 1;
            Object objB = AbstractC0349s0.b(n0, this.l - n0.g(), k0, this);
            if (objB != obj2) {
                objB = Unit.a;
            }
            if (objB == obj2) {
                return obj2;
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
