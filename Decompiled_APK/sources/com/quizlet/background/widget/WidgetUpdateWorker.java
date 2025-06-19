package com.quizlet.background.widget;

import android.content.Context;
import androidx.work.CoroutineWorker;
import androidx.work.WorkerParameters;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class WidgetUpdateWorker extends CoroutineWorker {
    public final com.quizlet.data.interactor.widget.a g;
    public final a h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public WidgetUpdateWorker(@NotNull Context context, @NotNull WorkerParameters workParams, @NotNull com.quizlet.data.interactor.widget.a useCase, @NotNull a widgetUpdater) {
        super(context, workParams);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(workParams, "workParams");
        Intrinsics.checkNotNullParameter(useCase, "useCase");
        Intrinsics.checkNotNullParameter(widgetUpdater, "widgetUpdater");
        this.g = useCase;
        this.h = widgetUpdater;
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x007c, code lost:
    
        if (((androidx.camera.camera2.internal.concurrent.a) r6).T(false, r0) == r1) goto L33;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // androidx.work.CoroutineWorker
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.h r6) throws java.lang.Throwable {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.background.widget.b
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.background.widget.b r0 = (com.quizlet.background.widget.b) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L1a
        L13:
            com.quizlet.background.widget.b r0 = new com.quizlet.background.widget.b
            kotlin.coroutines.jvm.internal.c r6 = (kotlin.coroutines.jvm.internal.c) r6
            r0.<init>(r5, r6)
        L1a:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3a
            if (r2 == r4) goto L34
            if (r2 != r3) goto L2c
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L7f
        L2c:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L34:
            com.quizlet.background.widget.WidgetUpdateWorker r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L53
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.background.widget.a r6 = r5.h
            androidx.camera.camera2.internal.concurrent.a r6 = (androidx.camera.camera2.internal.concurrent.a) r6
            int r6 = r6.b
            r0.j = r5
            r0.m = r4
            com.quizlet.data.interactor.widget.a r2 = r5.g
            com.quizlet.data.repository.widget.b r2 = r2.a
            java.lang.Object r6 = r2.l(r6, r0)
            if (r6 != r1) goto L52
            goto L7e
        L52:
            r2 = r5
        L53:
            com.quizlet.data.model.x2 r6 = (com.quizlet.data.model.x2) r6
            boolean r4 = r6 instanceof com.quizlet.data.model.D2
            if (r4 != 0) goto L6e
            boolean r4 = r6 instanceof com.quizlet.data.model.z2
            if (r4 == 0) goto L5e
            goto L6e
        L5e:
            boolean r6 = r6 instanceof com.quizlet.data.model.y2
            if (r6 == 0) goto L68
            androidx.work.v r6 = new androidx.work.v
            r6.<init>()
            return r6
        L68:
            kotlin.NoWhenBranchMatchedException r6 = new kotlin.NoWhenBranchMatchedException
            r6.<init>()
            throw r6
        L6e:
            com.quizlet.background.widget.a r6 = r2.h
            r2 = 0
            r0.j = r2
            r0.m = r3
            androidx.camera.camera2.internal.concurrent.a r6 = (androidx.camera.camera2.internal.concurrent.a) r6
            r2 = 0
            java.lang.Object r6 = r6.T(r2, r0)
            if (r6 != r1) goto L7f
        L7e:
            return r1
        L7f:
            androidx.work.w r6 = androidx.work.x.a()
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.background.widget.WidgetUpdateWorker.a(kotlin.coroutines.h):java.lang.Object");
    }
}
