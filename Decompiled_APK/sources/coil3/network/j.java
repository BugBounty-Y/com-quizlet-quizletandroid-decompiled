package coil3.network;

import android.content.Context;
import androidx.lifecycle.C1247h;
import coil3.y;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class j implements coil3.fetch.f {
    public final kotlin.u a;
    public final kotlin.u b;
    public final com.quizlet.data.interactor.school.b c;

    public j(androidx.lifecycle.compose.f fVar) {
        androidx.lifecycle.compose.f fVar2 = new androidx.lifecycle.compose.f(8);
        i iVar = i.a;
        this.a = kotlin.l.b(fVar);
        this.b = kotlin.l.b(fVar2);
        com.quizlet.data.interactor.school.b bVar = new com.quizlet.data.interactor.school.b(6, false);
        bVar.b = iVar;
        bVar.c = coil3.network.internal.b.a;
        this.c = bVar;
    }

    @Override // coil3.fetch.f
    public final coil3.fetch.g a(Object obj, coil3.request.m mVar, coil3.u uVar) {
        y yVar = (y) obj;
        if (!Intrinsics.b(yVar.c, "http") && !Intrinsics.b(yVar.c, "https")) {
            return null;
        }
        String str = yVar.a;
        kotlin.u uVar2 = this.a;
        kotlin.u uVarB = kotlin.l.b(new C1247h(uVar, 10));
        kotlin.u uVar3 = this.b;
        com.quizlet.data.interactor.school.b bVar = this.c;
        Context context = mVar.a;
        Object obj2 = bVar.c;
        coil3.network.internal.b bVar2 = coil3.network.internal.b.a;
        if (obj2 == bVar2) {
            synchronized (bVar) {
                obj2 = bVar.c;
                if (obj2 == bVar2) {
                    Function1 function1 = (Function1) bVar.b;
                    Intrinsics.d(function1);
                    Object objInvoke = function1.invoke(context);
                    bVar.c = objInvoke;
                    bVar.b = null;
                    obj2 = objInvoke;
                }
            }
        }
        return new q(str, mVar, uVar2, uVarB, uVar3, (e) obj2);
    }
}
