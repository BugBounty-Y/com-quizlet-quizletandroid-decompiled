package androidx.compose.material3;

import androidx.compose.animation.C0297y;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* renamed from: androidx.compose.material3.r1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0711r1 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ androidx.compose.foundation.interaction.l l;
    public final /* synthetic */ C0744v1 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0711r1(androidx.compose.foundation.interaction.l lVar, C0744v1 c0744v1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = lVar;
        this.m = c0744v1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0711r1 c0711r1 = new C0711r1(this.l, this.m, hVar);
        c0711r1.k = obj;
        return c0711r1;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0711r1) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
            ArrayList arrayList = new ArrayList();
            InterfaceC4992i interfaceC4992iB = this.l.b();
            C0297y c0297y = new C0297y(arrayList, c, this.m, 2);
            this.j = 1;
            if (interfaceC4992iB.b(c0297y, this) == aVar) {
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
