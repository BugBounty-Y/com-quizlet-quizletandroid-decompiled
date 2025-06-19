package com.quizlet.features.settings.composables.deleteaccount;

import android.content.Context;
import android.widget.Toast;
import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.quizlet.features.settings.viewmodels.o;
import com.quizlet.features.settings.viewmodels.s;
import com.quizlet.features.settings.viewmodels.u;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.q;
import kotlin.r;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.features.infra.google.e k;
    public final /* synthetic */ o l;
    public final /* synthetic */ Context m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(com.quizlet.features.infra.google.e eVar, o oVar, Context context, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = oVar;
        this.m = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objA;
        String token;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            objA = this.k.a(this);
            if (objA == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objA = ((r) obj).a;
        }
        p pVar = r.b;
        if (!(objA instanceof q) && (token = (String) objA) != null) {
            u uVar = (u) this.l;
            uVar.getClass();
            Intrinsics.checkNotNullParameter(token, "token");
            uVar.E();
            E.A(p0.j(uVar), null, null, new s(uVar, token, null), 3);
        }
        if (r.a(objA) != null) {
            Context context = this.m;
            Intrinsics.checkNotNullParameter(context, "context");
            Toast.makeText(context, R.string.client_error_net_exception, 0).show();
        }
        return Unit.a;
    }
}
