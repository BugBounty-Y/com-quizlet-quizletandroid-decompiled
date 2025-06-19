package androidx.compose.material3;

import android.window.BackEvent;
import androidx.compose.animation.core.C0238e;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.d2, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0604d2 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0238e k;
    public final /* synthetic */ BackEvent l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0604d2(C0238e c0238e, BackEvent backEvent, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0238e;
        this.l = backEvent;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0604d2(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0604d2) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            Float f = new Float(androidx.compose.material3.internal.M.a.b(this.l.getProgress()));
            this.j = 1;
            if (this.k.f(f, this) == aVar) {
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
