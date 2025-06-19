package com.quizlet.features.folders.changetags.viewmodel;

import androidx.compose.material.ripple.r;
import androidx.lifecycle.m0;
import androidx.lifecycle.w0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.features.folders.changetags.data.f;
import com.quizlet.generated.enums.y1;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class d extends w0 implements e {
    public final r b;
    public final FolderLogger c;
    public final long d;
    public String e;
    public y1 f;
    public final d0 g;
    public final s0 h;

    public d(m0 savedStateHandle, r addToFolderPresenterUseCase, FolderLogger folderLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(addToFolderPresenterUseCase, "addToFolderPresenterUseCase");
        Intrinsics.checkNotNullParameter(folderLogger, "folderLogger");
        this.b = addToFolderPresenterUseCase;
        this.c = folderLogger;
        Long l = (Long) savedStateHandle.a("folderId");
        if (l == null) {
            throw new IllegalArgumentException("Missing ARG_FOLDER_ID");
        }
        this.d = l.longValue();
        this.g = e0.b(0, 0, null, 7);
        this.h = e0.c(f.e);
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0086, code lost:
    
        if (r11.emit(r13, r0) == r1) goto L24;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.features.folders.changetags.viewmodel.d r11, com.quizlet.data.interactor.folderstudymaterial.e r12, kotlinx.collections.immutable.c r13, kotlin.coroutines.jvm.internal.c r14) {
        /*
            r11.getClass()
            boolean r0 = r14 instanceof com.quizlet.features.folders.changetags.viewmodel.a
            if (r0 == 0) goto L16
            r0 = r14
            com.quizlet.features.folders.changetags.viewmodel.a r0 = (com.quizlet.features.folders.changetags.viewmodel.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.features.folders.changetags.viewmodel.a r0 = new com.quizlet.features.folders.changetags.viewmodel.a
            r0.<init>(r11, r14)
        L1b:
            java.lang.Object r14 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3f
            if (r2 == r4) goto L35
            if (r2 != r3) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L89
        L2d:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L35:
            com.quizlet.features.folders.changetags.viewmodel.d r11 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r14)
            kotlin.r r14 = (kotlin.r) r14
            java.lang.Object r12 = r14.a
            goto L5e
        L3f:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            java.lang.String r6 = r11.e
            com.quizlet.generated.enums.y1 r7 = r11.f
            java.util.List r10 = kotlin.collections.CollectionsKt.w0(r13)
            com.quizlet.eventlogger.features.folder.FolderLogger r5 = r11.c
            long r8 = r11.d
            r5.b(r6, r7, r8, r10)
            r0.j = r11
            r0.m = r4
            androidx.compose.material.ripple.r r13 = r11.b
            java.lang.Object r12 = r13.i(r12, r0)
            if (r12 != r1) goto L5e
            goto L88
        L5e:
            kotlinx.coroutines.flow.s0 r13 = r11.h
        L60:
            java.lang.Object r14 = r13.getValue()
            r4 = r14
            com.quizlet.features.folders.changetags.data.f r4 = (com.quizlet.features.folders.changetags.data.f) r4
            r6 = 0
            r9 = 7
            r5 = 0
            r7 = 0
            r8 = 0
            com.quizlet.features.folders.changetags.data.f r2 = com.quizlet.features.folders.changetags.data.f.a(r4, r5, r6, r7, r8, r9)
            boolean r14 = r13.k(r14, r2)
            if (r14 == 0) goto L60
            kotlinx.coroutines.flow.d0 r11 = r11.g
            kotlin.r r13 = new kotlin.r
            r13.<init>(r12)
            r12 = 0
            r0.j = r12
            r0.m = r3
            java.lang.Object r11 = r11.emit(r13, r0)
            if (r11 != r1) goto L89
        L88:
            return r1
        L89:
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.folders.changetags.viewmodel.d.A(com.quizlet.features.folders.changetags.viewmodel.d, com.quizlet.data.interactor.folderstudymaterial.e, kotlinx.collections.immutable.c, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static kotlinx.collections.immutable.c B(List list) {
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            if (obj instanceof com.quizlet.features.infra.folder.menu.data.e) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            if (((com.quizlet.features.infra.folder.menu.data.e) next).d) {
                arrayList2.add(next);
            }
        }
        ArrayList arrayList3 = new ArrayList(C.q(arrayList2, 10));
        Iterator it3 = arrayList2.iterator();
        while (it3.hasNext()) {
            arrayList3.add(Long.valueOf(((com.quizlet.features.infra.folder.menu.data.e) it3.next()).b));
        }
        return AbstractC3409x1.j(arrayList3);
    }
}
