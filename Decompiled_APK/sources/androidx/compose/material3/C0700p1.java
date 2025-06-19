package androidx.compose.material3;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.p1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0700p1 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0744v1 k;
    public final /* synthetic */ C0717s1 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0700p1(C0744v1 c0744v1, C0717s1 c0717s1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0744v1;
        this.l = c0717s1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0700p1(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0700p1) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0717s1 c0717s1 = this.l;
            this.j = 1;
            C0744v1 c0744v1 = this.k;
            c0744v1.a = c0717s1.a;
            c0744v1.b = c0717s1.b;
            c0744v1.c = c0717s1.d;
            c0744v1.d = c0717s1.c;
            Object objB = c0744v1.b(this);
            if (objB != aVar) {
                objB = Unit.a;
            }
            if (objB == aVar) {
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
