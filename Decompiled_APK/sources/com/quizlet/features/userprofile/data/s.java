package com.quizlet.features.userprofile.data;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.C4135i0;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class s extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ x k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(x xVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = xVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new s(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((s) create((C4135i0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object value;
        a aVarA;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            x xVar = this.k;
            s0 s0Var = xVar.k;
            Object value2 = s0Var.getValue();
            j jVar = value2 instanceof j ? (j) value2 : null;
            if (jVar != null) {
                do {
                    value = s0Var.getValue();
                    String str = this.l;
                    aVarA = jVar.a;
                    if (str != null && str.length() != 0) {
                        aVarA = a.a(aVarA, str, 14);
                    }
                } while (!s0Var.k(value, j.a(jVar, aVarA)));
            }
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            com.quizlet.qutils.string.f fVar = new com.quizlet.qutils.string.f(R.string.user_settings_profile_image_changed, C4933y.P(args));
            this.j = 1;
            Object objEmit = xVar.m.emit(new com.quizlet.features.infra.snackbar.m(fVar), this);
            if (objEmit != kotlin.coroutines.intrinsics.a.a) {
                objEmit = Unit.a;
            }
            if (objEmit == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
