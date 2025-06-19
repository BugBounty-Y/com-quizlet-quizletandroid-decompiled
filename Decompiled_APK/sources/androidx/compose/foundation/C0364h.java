package androidx.compose.foundation;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0364h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ AbstractC0368j j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0364h(AbstractC0368j abstractC0368j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = abstractC0368j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0364h(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0364h) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        AbstractC0368j abstractC0368j = this.j;
        androidx.compose.foundation.interaction.h hVar = abstractC0368j.A;
        if (hVar != null) {
            androidx.compose.foundation.interaction.i iVar = new androidx.compose.foundation.interaction.i(hVar);
            androidx.compose.foundation.interaction.l lVar = abstractC0368j.p;
            if (lVar != null) {
                kotlinx.coroutines.E.A(abstractC0368j.A0(), null, null, new C0301b(lVar, iVar, null), 3);
            }
            abstractC0368j.A = null;
        }
        return Unit.a;
    }
}
