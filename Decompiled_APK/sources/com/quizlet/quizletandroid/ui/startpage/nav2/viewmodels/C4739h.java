package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4716l;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4739h extends w0 {
    public final androidx.work.impl.model.c b;
    public final com.quizlet.shared.usecase.folderstudymaterials.a c;
    public final com.quizlet.shared.usecase.folderstudymaterials.a d;
    public final com.quizlet.quizletandroid.ui.startpage.nav2.logging.c e;
    public final com.google.firebase.crashlytics.internal.settings.b f;
    public final androidx.work.impl.model.e g;
    public final com.quizlet.data.repository.user.a h;
    public final s0 i;
    public final d0 j;
    public final d0 k;

    public C4739h(androidx.work.impl.model.c userProperties, com.quizlet.shared.usecase.folderstudymaterials.a canCreateClassFeature, com.quizlet.shared.usecase.folderstudymaterials.a canCreateFolderFeature, com.quizlet.quizletandroid.ui.startpage.nav2.logging.c homeNavigationEventLogger, com.google.firebase.crashlytics.internal.settings.b checkNotesEligibilityUseCase, FolderLogger folderEventLogger, androidx.work.impl.model.e practiceTestUploadEligibilityFeature, com.quizlet.data.repository.user.a creationMenuRedesignFeature) {
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(canCreateClassFeature, "canCreateClassFeature");
        Intrinsics.checkNotNullParameter(canCreateFolderFeature, "canCreateFolderFeature");
        Intrinsics.checkNotNullParameter(homeNavigationEventLogger, "homeNavigationEventLogger");
        Intrinsics.checkNotNullParameter(checkNotesEligibilityUseCase, "checkNotesEligibilityUseCase");
        Intrinsics.checkNotNullParameter(folderEventLogger, "folderEventLogger");
        Intrinsics.checkNotNullParameter(practiceTestUploadEligibilityFeature, "practiceTestUploadEligibilityFeature");
        Intrinsics.checkNotNullParameter(creationMenuRedesignFeature, "creationMenuRedesignFeature");
        this.b = userProperties;
        this.c = canCreateClassFeature;
        this.d = canCreateFolderFeature;
        this.e = homeNavigationEventLogger;
        this.f = checkNotesEligibilityUseCase;
        this.g = practiceTestUploadEligibilityFeature;
        this.h = creationMenuRedesignFeature;
        this.i = e0.c(new C4716l(true, true, true, true, false));
        this.j = e0.b(0, 0, null, 7);
        this.k = e0.b(0, 0, null, 7);
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4732a(this, null), 3);
        folderEventLogger.setScreenName("bottom_nav");
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x0058, code lost:
    
        if (r5.emit(r6, r0) == r1) goto L21;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object A(com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4739h r5, com.quizlet.quizletandroid.ui.startpage.nav2.model.InterfaceC4715k r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5.getClass()
            boolean r0 = r7 instanceof com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4733b
            if (r0 == 0) goto L16
            r0 = r7
            com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.b r0 = (com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4733b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.b r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.b
            r0.<init>(r5, r7)
        L1b:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3b
            if (r2 == r4) goto L35
            if (r2 != r3) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L5b
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.h r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4b
        L3b:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlinx.coroutines.flow.d0 r7 = r5.j
            r0.j = r5
            r0.m = r4
            java.lang.Object r6 = r7.emit(r6, r0)
            if (r6 != r1) goto L4b
            goto L5a
        L4b:
            kotlinx.coroutines.flow.d0 r5 = r5.k
            kotlin.Unit r6 = kotlin.Unit.a
            r7 = 0
            r0.j = r7
            r0.m = r3
            java.lang.Object r5 = r5.emit(r6, r0)
            if (r5 != r1) goto L5b
        L5a:
            return r1
        L5b:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4739h.A(com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.h, com.quizlet.quizletandroid.ui.startpage.nav2.model.k, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
