package androidx.compose.foundation.text.input.internal;

import androidx.compose.ui.platform.V;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.input.internal.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0500f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ androidx.activity.compose.d l;
    public final /* synthetic */ g m;
    public final /* synthetic */ w n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0500f(androidx.activity.compose.d dVar, g gVar, w wVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = dVar;
        this.m = gVar;
        this.n = wVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0500f c0500f = new C0500f(this.l, this.m, this.n, hVar);
        c0500f.k = obj;
        return c0500f;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((C0500f) create((V) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C0499e c0499e = new C0499e((V) this.k, this.l, this.m, this.n, null);
            this.j = 1;
            if (kotlinx.coroutines.E.m(c0499e, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        throw new KotlinNothingValueException();
    }
}
