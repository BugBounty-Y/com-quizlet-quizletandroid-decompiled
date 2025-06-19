package com.quizlet.remote.model.folder;

import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_barcode.Z;
import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.remote.model.base.ApiPostBody;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes3.dex */
public final class p {
    public final com.quizlet.login.authentication.login.a a;
    public final com.quizlet.quizletandroid.ui.folder.logging.a b;
    public final com.quizlet.remote.model.folder.course.a c;
    public final AbstractC5040y d;

    public p(com.quizlet.login.authentication.login.a dataSource, com.quizlet.quizletandroid.ui.folder.logging.a mapper, com.quizlet.quizletandroid.ui.joincontenttofolder.i newFolderMapper, com.quizlet.remote.model.folder.course.a courseStudyMaterialRecommendationsResponseMapper, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        Intrinsics.checkNotNullParameter(newFolderMapper, "newFolderMapper");
        Intrinsics.checkNotNullParameter(courseStudyMaterialRecommendationsResponseMapper, "courseStudyMaterialRecommendationsResponseMapper");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = dataSource;
        this.b = mapper;
        this.c = courseStudyMaterialRecommendationsResponseMapper;
        this.d = ioDispatcher;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.remote.model.folder.f
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.remote.model.folder.f r0 = (com.quizlet.remote.model.folder.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.remote.model.folder.f r0 = new com.quizlet.remote.model.folder.f
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L43
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.remote.model.folder.g r7 = new com.quizlet.remote.model.folder.g
            r2 = 0
            r7.<init>(r4, r5, r2)
            r0.l = r3
            kotlinx.coroutines.y r5 = r4.d
            java.lang.Object r7 = kotlinx.coroutines.E.J(r5, r7, r0)
            if (r7 != r1) goto L43
            return r1
        L43:
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r5 = r7.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.folder.p.a(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(long r11, java.util.List r13, kotlin.coroutines.jvm.internal.c r14) {
        /*
            r10 = this;
            boolean r0 = r14 instanceof com.quizlet.remote.model.folder.h
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.remote.model.folder.h r0 = (com.quizlet.remote.model.folder.h) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.remote.model.folder.h r0 = new com.quizlet.remote.model.folder.h
            r0.<init>(r10, r14)
        L18:
            java.lang.Object r14 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L30
            if (r2 != r3) goto L28
            androidx.glance.appwidget.protobuf.Z.e(r14)
            r5 = r10
            goto L47
        L28:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L30:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            com.quizlet.remote.model.folder.i r4 = new com.quizlet.remote.model.folder.i
            r9 = 0
            r5 = r10
            r6 = r11
            r8 = r13
            r4.<init>(r5, r6, r8, r9)
            r0.l = r3
            kotlinx.coroutines.y r11 = r5.d
            java.lang.Object r14 = kotlinx.coroutines.E.J(r11, r4, r0)
            if (r14 != r1) goto L47
            return r1
        L47:
            kotlin.r r14 = (kotlin.r) r14
            java.lang.Object r11 = r14.a
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.folder.p.b(long, java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.remote.model.folder.j
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.remote.model.folder.j r0 = (com.quizlet.remote.model.folder.j) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.remote.model.folder.j r0 = new com.quizlet.remote.model.folder.j
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L43
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.remote.model.folder.k r7 = new com.quizlet.remote.model.folder.k
            r2 = 0
            r7.<init>(r4, r5, r2)
            r0.l = r3
            kotlinx.coroutines.y r5 = r4.d
            java.lang.Object r7 = kotlinx.coroutines.E.J(r5, r7, r0)
            if (r7 != r1) goto L43
            return r1
        L43:
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r5 = r7.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.folder.p.c(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable d(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.remote.model.folder.l
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.remote.model.folder.l r0 = (com.quizlet.remote.model.folder.l) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.remote.model.folder.l r0 = new com.quizlet.remote.model.folder.l
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.quizlet.remote.model.folder.p r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L42
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r4
            r0.m = r3
            com.quizlet.login.authentication.login.a r7 = r4.a
            java.lang.Object r7 = r7.h(r5, r0)
            if (r7 != r1) goto L41
            return r1
        L41:
            r5 = r4
        L42:
            com.quizlet.remote.model.base.ApiThreeWrapper r7 = (com.quizlet.remote.model.base.ApiThreeWrapper) r7
            com.quizlet.remote.model.base.ApiResponse r6 = r7.a()
            com.quizlet.remote.model.folder.course.CourseStudyMaterialRecommendationsResponse r6 = (com.quizlet.remote.model.folder.course.CourseStudyMaterialRecommendationsResponse) r6
            if (r6 == 0) goto L53
            com.quizlet.remote.model.folder.course.a r5 = r5.c
            java.util.ArrayList r5 = r5.a(r6)
            return r5
        L53:
            kotlin.collections.K r5 = kotlin.collections.K.a
            java.lang.String r6 = "studyMaterials"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r6)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.folder.p.d(long, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(long r5, kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.remote.model.folder.m
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.remote.model.folder.m r0 = (com.quizlet.remote.model.folder.m) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.remote.model.folder.m r0 = new com.quizlet.remote.model.folder.m
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L43
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.remote.model.folder.n r7 = new com.quizlet.remote.model.folder.n
            r2 = 0
            r7.<init>(r4, r5, r2)
            r0.l = r3
            kotlinx.coroutines.y r5 = r4.d
            java.lang.Object r7 = kotlinx.coroutines.E.J(r5, r7, r0)
            if (r7 != r1) goto L43
            return r1
        L43:
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r5 = r7.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.folder.p.e(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final io.reactivex.rxjava3.core.p f(List list) {
        io.reactivex.rxjava3.core.p pVarG;
        io.reactivex.rxjava3.core.p pVarG2;
        ArrayList arrayListM = assistantMode.refactored.a.m("folders", list);
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            AbstractC4119d0 abstractC4119d0 = (AbstractC4119d0) obj;
            if (abstractC4119d0.e() && abstractC4119d0.d() && abstractC4119d0.a() > 0) {
                arrayListM.add(obj);
            } else {
                arrayList.add(obj);
            }
        }
        boolean zIsEmpty = arrayListM.isEmpty();
        com.quizlet.login.authentication.login.a aVar = this.a;
        com.quizlet.quizletandroid.ui.folder.logging.a aVar2 = this.b;
        com.quizlet.remote.service.m mVar = (com.quizlet.remote.service.m) aVar.b;
        if (zIsEmpty) {
            pVarG = io.reactivex.rxjava3.core.p.f(K.a);
        } else {
            ArrayList folders = T.g(aVar2, arrayListM);
            Intrinsics.checkNotNullParameter(folders, "folders");
            com.quizlet.qutils.android.f transform = new com.quizlet.qutils.android.f(8);
            Intrinsics.checkNotNullParameter(folders, "<this>");
            Intrinsics.checkNotNullParameter(transform, "transform");
            ArrayList arrayList2 = new ArrayList();
            Iterator it2 = folders.iterator();
            while (it2.hasNext()) {
                Object objInvoke = transform.invoke(it2.next());
                if (objInvoke != null) {
                    arrayList2.add(objInvoke);
                }
            }
            pVarG = mVar.h(CollectionsKt.S(arrayList2, ",", null, null, null, 62)).g(new o(this, folders));
            Intrinsics.checkNotNullExpressionValue(pVarG, "map(...)");
        }
        if (arrayList.isEmpty()) {
            pVarG2 = io.reactivex.rxjava3.core.p.f(K.a);
        } else {
            ArrayList data = T.g(aVar2, arrayList);
            Intrinsics.checkNotNullParameter(data, "data");
            pVarG2 = mVar.e(new ApiPostBody<>(data)).g(new o(this, data));
            Intrinsics.checkNotNullExpressionValue(pVarG2, "map(...)");
        }
        return Z.b(pVarG, pVarG2);
    }
}
