package androidx.compose.foundation.text.input.internal;

import androidx.compose.ui.platform.F0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class v extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ w k;
    public final /* synthetic */ C0500f l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(w wVar, C0500f c0500f, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = wVar;
        this.l = c0500f;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new v(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((v) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            throw new KotlinNothingValueException();
        }
        Z.e(obj);
        this.j = 1;
        F0.a(this.k, this.l, this);
        return aVar;
    }
}
