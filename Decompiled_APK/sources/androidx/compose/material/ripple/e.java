package androidx.compose.material.ripple;

import androidx.compose.foundation.text.C0494i0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ androidx.compose.foundation.interaction.k l;
    public final /* synthetic */ a m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(androidx.compose.foundation.interaction.k kVar, a aVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = kVar;
        this.m = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        e eVar = new e(this.l, this.m, hVar);
        eVar.k = obj;
        return eVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C c = (C) this.k;
            InterfaceC4992i interfaceC4992iB = this.l.b();
            C0494i0 c0494i0 = new C0494i0(3, this.m, c);
            this.j = 1;
            if (interfaceC4992iB.b(c0494i0, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
