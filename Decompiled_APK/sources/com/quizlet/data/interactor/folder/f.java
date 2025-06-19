package com.quizlet.data.interactor.folder;

import androidx.compose.foundation.text.z0;
import com.quizlet.data.model.CreatedFolder;
import kotlin.collections.A;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f implements io.reactivex.rxjava3.functions.h {
    public final com.quizlet.data.repository.folder.i a;

    public f(com.quizlet.data.repository.folder.i folderRepository, int i) {
        switch (i) {
            case 1:
                this.a = folderRepository;
                break;
            default:
                Intrinsics.checkNotNullParameter(folderRepository, "folderRepository");
                this.a = folderRepository;
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.folder.d
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.folder.d r0 = (com.quizlet.data.interactor.folder.d) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folder.d r0 = new com.quizlet.data.interactor.folder.d
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r5 = r7.a
            return r5
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.l = r3
            com.quizlet.data.repository.folder.i r7 = r4.a
            java.lang.Object r5 = r7.b(r5, r0)
            if (r5 != r1) goto L41
            return r1
        L41:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folder.f.a(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        CreatedFolder folder = (CreatedFolder) obj;
        Intrinsics.checkNotNullParameter(folder, "folder");
        androidx.work.impl.model.c cVar = this.a.a;
        com.quizlet.remote.model.folder.p pVar = (com.quizlet.remote.model.folder.p) cVar.c;
        Intrinsics.checkNotNullParameter(folder, "folder");
        z0 z0Var = new z0(1, pVar, com.quizlet.remote.model.folder.p.class, "saveFolders", "saveFolders(Ljava/util/List;)Lio/reactivex/rxjava3/core/Single;", 0, 9);
        Intrinsics.checkNotNullParameter(z0Var, "<this>");
        io.reactivex.rxjava3.core.p pVar2 = (io.reactivex.rxjava3.core.p) z0Var.invoke(A.b(folder));
        Intrinsics.checkNotNullParameter(pVar2, "<this>");
        io.reactivex.rxjava3.internal.operators.single.g gVarG = pVar2.g(com.quizlet.data.ext.a.d);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return gVarG.e(new com.lyft.android.scissors.b((com.quizlet.local.ormlite.models.bookmark.a) cVar.b, 10));
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.folder.e
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.folder.e r0 = (com.quizlet.data.interactor.folder.e) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folder.e r0 = new com.quizlet.data.interactor.folder.e
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r5 = r7.a
            goto L41
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.l = r3
            com.quizlet.data.repository.folder.i r7 = r4.a
            java.lang.Object r5 = r7.e(r5, r0)
            if (r5 != r1) goto L41
            return r1
        L41:
            java.lang.Throwable r6 = kotlin.r.a(r5)
            if (r6 != 0) goto L48
            return r5
        L48:
            java.lang.Boolean r5 = java.lang.Boolean.FALSE
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.interactor.folder.f.b(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
