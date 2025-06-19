package androidx.compose.ui.scrollcapture;

import androidx.compose.runtime.L0;
import androidx.glance.appwidget.protobuf.Z;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ f k;
    public final /* synthetic */ Runnable l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(f fVar, Runnable runnable, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = fVar;
        this.l = runnable;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        f fVar = this.k;
        if (i == 0) {
            Z.e(obj);
            j jVar = fVar.e;
            this.j = 1;
            Object objB = jVar.b(DefinitionKt.NO_Float_VALUE - jVar.b, this);
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
            Z.e(obj);
        }
        ((L0) fVar.c.a).setValue(Boolean.FALSE);
        this.l.run();
        return Unit.a;
    }
}
