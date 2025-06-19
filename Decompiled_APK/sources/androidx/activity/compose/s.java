package androidx.activity.compose;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class s extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ r j;
    public final /* synthetic */ boolean k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(r rVar, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = rVar;
        this.k = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new s(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((s) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r3v2, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.o] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        com.bumptech.glide.manager.p pVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        r rVar = this.j;
        boolean z = this.k;
        if (!z && !rVar.g && rVar.a && (pVar = rVar.f) != null) {
            pVar.e();
        }
        rVar.a = z;
        ?? r3 = rVar.c;
        if (r3 != 0) {
            r3.invoke();
        }
        return Unit.a;
    }
}
