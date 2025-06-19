package androidx.compose.foundation;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0309f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ AbstractC0368j k;
    public final /* synthetic */ androidx.compose.foundation.interaction.o l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0309f(AbstractC0368j abstractC0368j, androidx.compose.foundation.interaction.o oVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = abstractC0368j;
        this.l = oVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0309f(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0309f) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.compose.foundation.interaction.l lVar = this.k.p;
            if (lVar != null) {
                androidx.compose.foundation.interaction.p pVar = new androidx.compose.foundation.interaction.p(this.l);
                this.j = 1;
                if (lVar.c(pVar, this) == aVar) {
                    return aVar;
                }
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
