package com.quizlet.features.setpage.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.X;
import com.quizlet.features.infra.folder.menu.data.AddToFolderException;
import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ P k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        u uVar = new u(this.k, hVar);
        uVar.j = obj;
        return uVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((u) create((com.quizlet.features.infra.folder.menu.data.q) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        com.quizlet.qutils.string.f fVar;
        com.quizlet.qutils.string.f fVar2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.infra.folder.menu.data.q qVar = (com.quizlet.features.infra.folder.menu.data.q) this.j;
        boolean z = qVar instanceof com.quizlet.features.infra.folder.menu.data.m;
        P p = this.k;
        if (z) {
            X x = p.p1;
            com.quizlet.features.infra.snackbar.d dVar = com.quizlet.features.infra.snackbar.k.b;
            com.quizlet.features.infra.folder.menu.data.m mVar = (com.quizlet.features.infra.folder.menu.data.m) qVar;
            AddToFolderException addToFolderException = mVar.b;
            boolean z2 = addToFolderException instanceof AddToFolderException.Adding;
            String str = mVar.a;
            if (z2) {
                Object[] args = {str};
                Intrinsics.checkNotNullParameter(args, "args");
                fVar2 = new com.quizlet.qutils.string.f(R.string.error_added_material_to_folder, C4933y.P(args));
            } else if (addToFolderException instanceof AddToFolderException.Removing) {
                Object[] args2 = {str};
                Intrinsics.checkNotNullParameter(args2, "args");
                fVar2 = new com.quizlet.qutils.string.f(R.string.error_removed_material_from_folder, C4933y.P(args2));
            } else {
                if (!(addToFolderException instanceof AddToFolderException.Multi)) {
                    throw new NoWhenBranchMatchedException();
                }
                Object[] args3 = new Object[0];
                Intrinsics.checkNotNullParameter(args3, "args");
                fVar2 = new com.quizlet.qutils.string.f(R.string.error_save_to_multiple_folders, C4933y.P(args3));
            }
            x.l(new com.quizlet.features.infra.snackbar.l(dVar, -1, fVar2, null, null, 120));
        } else if (qVar instanceof com.quizlet.features.infra.folder.menu.data.n) {
            X x2 = p.p1;
            com.quizlet.features.infra.snackbar.d dVar2 = com.quizlet.features.infra.snackbar.k.b;
            Object[] args4 = new Object[0];
            Intrinsics.checkNotNullParameter(args4, "args");
            x2.l(new com.quizlet.features.infra.snackbar.l(dVar2, -1, new com.quizlet.qutils.string.f(R.string.client_error_net_exception, C4933y.P(args4)), null, null, 120));
        } else if (qVar instanceof com.quizlet.features.infra.folder.menu.data.o) {
            X x3 = p.p1;
            com.quizlet.features.infra.snackbar.d dVar3 = com.quizlet.features.infra.snackbar.k.b;
            com.quizlet.features.infra.folder.menu.data.o oVar = (com.quizlet.features.infra.folder.menu.data.o) qVar;
            com.quizlet.data.interactor.folderstudymaterial.g gVar = oVar.b;
            boolean z3 = gVar instanceof com.quizlet.data.interactor.folderstudymaterial.d;
            String str2 = oVar.a;
            if (z3) {
                Object[] args5 = {str2};
                Intrinsics.checkNotNullParameter(args5, "args");
                fVar = new com.quizlet.qutils.string.f(R.string.removed_material_from_folder, C4933y.P(args5));
            } else if (gVar instanceof com.quizlet.data.interactor.folderstudymaterial.f) {
                Object[] args6 = {str2};
                Intrinsics.checkNotNullParameter(args6, "args");
                fVar = new com.quizlet.qutils.string.f(R.string.added_material_to_folder, C4933y.P(args6));
            } else {
                if (!(gVar instanceof com.quizlet.data.interactor.folderstudymaterial.e)) {
                    throw new NoWhenBranchMatchedException();
                }
                Object[] args7 = new Object[0];
                Intrinsics.checkNotNullParameter(args7, "args");
                fVar = new com.quizlet.qutils.string.f(R.string.save_to_multiple_folders_changes_saved, C4933y.P(args7));
            }
            Object[] args8 = new Object[0];
            Intrinsics.checkNotNullParameter(args8, "args");
            x3.l(new com.quizlet.features.infra.snackbar.l(dVar3, -1, fVar, new com.quizlet.qutils.string.f(R.string.undo, C4933y.P(args8)), new com.quizlet.features.questionnaire.screens.c(7, p, qVar), 40));
        } else if (qVar instanceof com.quizlet.features.infra.folder.menu.data.p) {
            X x4 = p.p1;
            com.quizlet.features.infra.snackbar.d dVar4 = com.quizlet.features.infra.snackbar.k.b;
            Object[] args9 = new Object[0];
            Intrinsics.checkNotNullParameter(args9, "args");
            x4.l(new com.quizlet.features.infra.snackbar.l(dVar4, -1, new com.quizlet.qutils.string.f(R.string.add_remove_material_undone, C4933y.P(args9)), null, null, 120));
        }
        return Unit.a;
    }
}
