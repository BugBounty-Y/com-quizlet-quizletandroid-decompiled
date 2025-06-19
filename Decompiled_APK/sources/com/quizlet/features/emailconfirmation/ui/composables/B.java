package com.quizlet.features.emailconfirmation.ui.composables;

import android.content.Context;
import androidx.compose.material3.O3;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.V;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class B extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ O3 l;
    public final /* synthetic */ Context m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(O3 o3, Context context, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = o3;
        this.m = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        B b = new B(this.l, this.m, hVar);
        b.k = obj;
        return b;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((B) create((com.quizlet.features.emailconfirmation.data.events.c) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objD;
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.features.emailconfirmation.data.events.c cVar = (com.quizlet.features.emailconfirmation.data.events.c) this.k;
            this.j = 1;
            int iOrdinal = cVar.ordinal();
            O3 o3 = this.l;
            Context context = this.m;
            if (iOrdinal == 0) {
                objD = V.d(o3, true, context, this);
                if (objD != obj2) {
                    objD = Unit.a;
                }
            } else if (iOrdinal == 1) {
                String string = context.getString(R.string.resend_magic_link_email_not_found);
                Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                objD = O3.b(o3, string, this);
                if (objD != obj2) {
                    objD = Unit.a;
                }
            } else {
                if (iOrdinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                objD = V.d(o3, false, context, this);
                if (objD != obj2) {
                    objD = Unit.a;
                }
            }
            if (objD == obj2) {
                return obj2;
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
