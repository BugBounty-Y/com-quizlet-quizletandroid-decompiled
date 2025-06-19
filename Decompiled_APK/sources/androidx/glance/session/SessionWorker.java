package androidx.glance.session;

import android.content.Context;
import androidx.work.C1437k;
import androidx.work.CoroutineWorker;
import androidx.work.WorkerParameters;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.O;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class SessionWorker extends CoroutineWorker {
    public final WorkerParameters g;
    public final InterfaceC1233k h;
    public final I i;
    public final AbstractC5040y j;
    public final String k;

    public SessionWorker(@NotNull Context context, @NotNull WorkerParameters workerParameters, @NotNull InterfaceC1233k interfaceC1233k, @NotNull I i, @NotNull AbstractC5040y abstractC5040y) {
        super(context, workerParameters);
        this.g = workerParameters;
        this.h = interfaceC1233k;
        this.i = i;
        this.j = abstractC5040y;
        C1437k inputData = getInputData();
        interfaceC1233k.getClass();
        String strC = inputData.c("KEY");
        if (strC == null) {
            throw new IllegalStateException("SessionWorker must be started with a key");
        }
        this.k = strC;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    @Override // androidx.work.CoroutineWorker
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.h r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof androidx.glance.session.r
            if (r0 == 0) goto L13
            r0 = r6
            androidx.glance.session.r r0 = (androidx.glance.session.r) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L1a
        L13:
            androidx.glance.session.r r0 = new androidx.glance.session.r
            kotlin.coroutines.jvm.internal.c r6 = (kotlin.coroutines.jvm.internal.c) r6
            r0.<init>(r5, r6)
        L1a:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L47
        L29:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            androidx.glance.session.I r6 = r5.i
            androidx.camera.camera2.internal.s0 r6 = r6.d
            androidx.glance.session.x r2 = new androidx.glance.session.x
            r4 = 0
            r2.<init>(r5, r4)
            r0.l = r3
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.AbstractC3397u1.h(r6, r2, r0)
            if (r6 != r1) goto L47
            return r1
        L47:
            androidx.work.x r6 = (androidx.work.x) r6
            if (r6 != 0) goto L69
            java.util.LinkedHashMap r6 = new java.util.LinkedHashMap
            r6.<init>()
            java.lang.String r0 = "TIMEOUT_EXIT_REASON"
            java.lang.String r1 = "key"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            java.lang.Boolean r1 = java.lang.Boolean.TRUE
            r6.put(r0, r1)
            androidx.work.k r0 = new androidx.work.k
            r0.<init>(r6)
            com.google.android.gms.internal.mlkit_vision_camera.AbstractC3390s2.d(r0)
            androidx.work.w r6 = new androidx.work.w
            r6.<init>(r0)
        L69:
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.session.SessionWorker.a(kotlin.coroutines.h):java.lang.Object");
    }

    @Override // androidx.work.CoroutineWorker
    public final AbstractC5040y b() {
        return this.j;
    }

    public SessionWorker(@NotNull Context context, @NotNull WorkerParameters workerParameters) {
        this(context, workerParameters, q.a, null, null, 24, null);
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public SessionWorker(Context context, WorkerParameters workerParameters, InterfaceC1233k interfaceC1233k, I i, AbstractC5040y abstractC5040y, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        InterfaceC1233k interfaceC1233k2 = (i2 & 4) != 0 ? q.a : interfaceC1233k;
        I i3 = (i2 & 8) != 0 ? new I() : i;
        if ((i2 & 16) != 0) {
            kotlinx.coroutines.scheduling.e eVar = O.a;
            abstractC5040y = kotlinx.coroutines.internal.m.a;
        }
        this(context, workerParameters, interfaceC1233k2, i3, abstractC5040y);
    }
}
