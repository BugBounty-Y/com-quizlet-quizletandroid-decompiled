package androidx.compose.foundation.text;

import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class C0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public InterfaceC0773a0 j;
    public int k;
    public final /* synthetic */ InterfaceC0773a0 l;
    public final /* synthetic */ boolean m;
    public final /* synthetic */ androidx.compose.foundation.interaction.l n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0(InterfaceC0773a0 interfaceC0773a0, boolean z, androidx.compose.foundation.interaction.l lVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = interfaceC0773a0;
        this.m = z;
        this.n = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        InterfaceC0773a0 interfaceC0773a0;
        InterfaceC0773a0 interfaceC0773a02;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            interfaceC0773a0 = this.l;
            androidx.compose.foundation.interaction.o oVar = (androidx.compose.foundation.interaction.o) interfaceC0773a0.getValue();
            if (oVar != null) {
                androidx.compose.foundation.interaction.j pVar = this.m ? new androidx.compose.foundation.interaction.p(oVar) : new androidx.compose.foundation.interaction.n(oVar);
                androidx.compose.foundation.interaction.l lVar = this.n;
                if (lVar != null) {
                    this.j = interfaceC0773a0;
                    this.k = 1;
                    if (lVar.c(pVar, this) == aVar) {
                        return aVar;
                    }
                    interfaceC0773a02 = interfaceC0773a0;
                }
                interfaceC0773a0.setValue(null);
            }
            return Unit.a;
        }
        if (i != 1) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        interfaceC0773a02 = this.j;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        interfaceC0773a0 = interfaceC0773a02;
        interfaceC0773a0.setValue(null);
        return Unit.a;
    }
}
