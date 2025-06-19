package com.quizlet.features.folders.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.features.folders.data.O0;
import com.quizlet.features.folders.data.U0;
import com.quizlet.features.folders.data.W0;
import java.util.Iterator;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.features.infra.models.folders.b k;
    public final /* synthetic */ N l;
    public final /* synthetic */ long m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(com.quizlet.features.infra.models.folders.b bVar, N n, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = bVar;
        this.l = n;
        this.m = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new r(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar;
        W0 u0;
        s0 s0Var;
        Object value;
        String str;
        kotlinx.collections.immutable.b bVar;
        kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            int iOrdinal = this.k.ordinal();
            N n = this.l;
            com.quizlet.features.folders.logging.e eVar = n.h;
            if (iOrdinal == 0 || iOrdinal == 1) {
                while (true) {
                    s0 s0Var2 = n.v;
                    Object value2 = s0Var2.getValue();
                    W0 w0 = (W0) value2;
                    com.quizlet.features.infra.models.folders.c cVar = null;
                    U0 u02 = w0 instanceof U0 ? (U0) w0 : null;
                    if (u02 != null && (bVar = u02.a) != null) {
                        Iterator<E> it2 = bVar.iterator();
                        while (true) {
                            if (!it2.hasNext()) {
                                break;
                            }
                            Object next = it2.next();
                            if (((com.quizlet.features.infra.models.folders.c) next).a == this.m) {
                                cVar = next;
                                break;
                            }
                        }
                        cVar = cVar;
                    }
                    String tagName = "ALL";
                    if (cVar != null && (str = cVar.c) != null && str.length() != 0) {
                        tagName = str;
                    }
                    n.t = tagName;
                    eVar.getClass();
                    Intrinsics.checkNotNullParameter(tagName, "tagName");
                    U0 u03 = u02;
                    com.quizlet.features.infra.models.folders.c cVar2 = cVar;
                    aVar = aVar2;
                    com.quizlet.features.folders.logging.e.b(eVar, n.r, "folder_tag_tab_clicked", null, null, null, null, new androidx.navigation.internal.h(tagName, 18), 124);
                    if (u03 != null) {
                        kotlinx.collections.immutable.b bVar2 = u03.a;
                        Intrinsics.checkNotNullParameter(bVar2, "<this>");
                        int iIndexOf = bVar2.indexOf(cVar2);
                        kotlinx.collections.immutable.b subFoldersUiData = u03.a;
                        Intrinsics.checkNotNullParameter(subFoldersUiData, "subFoldersUiData");
                        u0 = new U0(subFoldersUiData, iIndexOf, u03.c, u03.d, u03.e);
                    } else {
                        u0 = w0;
                    }
                    if (s0Var2.k(value2, u0)) {
                        break;
                    }
                    aVar2 = aVar;
                }
                do {
                    s0Var = n.w;
                    value = s0Var.getValue();
                } while (!s0Var.k(value, new O0(false, false)));
                this.j = 1;
                if (N.C(n, this) == aVar) {
                    return aVar;
                }
            } else {
                if (iOrdinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                eVar.getClass();
                EventLoggerExt.a(eVar.a, "folder_add_tag_clicked", new com.braze.requests.framework.m(6, n.r));
                n.M();
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
