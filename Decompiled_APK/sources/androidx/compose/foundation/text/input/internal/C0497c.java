package androidx.compose.foundation.text.input.internal;

import androidx.compose.animation.core.C0268t0;
import androidx.compose.runtime.C0776c;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.W;
import kotlinx.coroutines.flow.d0;

/* renamed from: androidx.compose.foundation.text.input.internal.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0497c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ g k;
    public final /* synthetic */ u l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0497c(g gVar, u uVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = gVar;
        this.l = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0497c(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0497c) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C0495a c0495a = C0495a.b;
            this.j = 1;
            if (C0776c.r(getContext()).P(new C0268t0(1, c0495a), this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                if (i != 2) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
                throw new KotlinNothingValueException();
            }
            Z.e(obj);
        }
        W wI = this.k.i();
        if (wI == null) {
            return Unit.a;
        }
        C0496b c0496b = new C0496b(this.l, 0);
        this.j = 2;
        d0.m((d0) wI, c0496b, this);
        return aVar;
    }
}
