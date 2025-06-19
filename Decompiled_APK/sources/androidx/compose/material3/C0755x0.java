package androidx.compose.material3;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.x0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0755x0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.compose.foundation.lazy.A k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0755x0(androidx.compose.foundation.lazy.A a, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0755x0(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0755x0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                androidx.compose.foundation.lazy.A a = this.k;
                int iA = a.d.a() + 1;
                this.j = 1;
                if (a.f(iA, 0, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
            }
        } catch (IllegalArgumentException unused) {
        }
        return Unit.a;
    }
}
