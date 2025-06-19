package androidx.compose.foundation.lazy.layout;

import androidx.compose.animation.core.C0238e;
import androidx.compose.runtime.L0;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.lazy.layout.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0452y extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ E k;
    public final /* synthetic */ androidx.compose.animation.core.D l;
    public final /* synthetic */ androidx.compose.ui.graphics.layer.b m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0452y(E e, androidx.compose.animation.core.D d, androidx.compose.ui.graphics.layer.b bVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = e;
        this.l = d;
        this.m = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0452y(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0452y) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        E e = this.k;
        try {
            if (i == 0) {
                androidx.glance.appwidget.protobuf.Z.e(obj);
                C0238e c0238e = e.p;
                Float f = new Float(DefinitionKt.NO_Float_VALUE);
                androidx.compose.animation.core.D d = this.l;
                C0450w c0450w = new C0450w(this.m, e, 1);
                this.j = 1;
                if (C0238e.c(c0238e, f, d, c0450w, this, 4) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
            }
            ((L0) e.k).setValue(Boolean.TRUE);
            e.e(false);
            return Unit.a;
        } catch (Throwable th) {
            int i2 = E.t;
            e.e(false);
            throw th;
        }
    }
}
