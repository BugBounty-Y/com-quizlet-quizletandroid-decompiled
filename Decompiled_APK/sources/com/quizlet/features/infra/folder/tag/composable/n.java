package com.quizlet.features.infra.folder.tag.composable;

import android.content.Context;
import androidx.compose.material3.O3;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ O3 l;
    public final /* synthetic */ Context m;
    public final /* synthetic */ Function2 n;
    public final /* synthetic */ x o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(O3 o3, Context context, Function2 function2, x xVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = o3;
        this.m = context;
        this.n = function2;
        this.o = xVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        n nVar = new n(this.l, this.m, this.n, this.o, hVar);
        nVar.k = obj;
        return nVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((com.quizlet.features.infra.folder.tag.screenstates.c) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.features.infra.folder.tag.screenstates.c cVar = (com.quizlet.features.infra.folder.tag.screenstates.c) this.k;
            if (Intrinsics.b(cVar, com.quizlet.features.infra.folder.tag.screenstates.a.a)) {
                String string = this.m.getString(R.string.new_tag_failed_add_tags);
                Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                this.j = 1;
                if (O3.b(this.l, string, this) == aVar) {
                    return aVar;
                }
            } else {
                if (!(cVar instanceof com.quizlet.features.infra.folder.tag.screenstates.b)) {
                    throw new NoWhenBranchMatchedException();
                }
                com.quizlet.features.infra.folder.tag.screenstates.b bVar = (com.quizlet.features.infra.folder.tag.screenstates.b) cVar;
                this.n.invoke(new Long(bVar.a), bVar.b);
                this.o.a();
                Unit unit = Unit.a;
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
