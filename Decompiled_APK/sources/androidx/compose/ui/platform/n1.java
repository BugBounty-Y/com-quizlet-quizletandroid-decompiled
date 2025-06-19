package androidx.compose.ui.platform;

import android.content.ContentResolver;
import android.content.Context;
import android.net.Uri;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes.dex */
public final class n1 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.channels.c j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ ContentResolver m;
    public final /* synthetic */ Uri n;
    public final /* synthetic */ o1 o;
    public final /* synthetic */ kotlinx.coroutines.channels.h p;
    public final /* synthetic */ Context q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n1(ContentResolver contentResolver, Uri uri, o1 o1Var, kotlinx.coroutines.channels.h hVar, Context context, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.m = contentResolver;
        this.n = uri;
        this.o = o1Var;
        this.p = hVar;
        this.q = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        kotlinx.coroutines.channels.h hVar2 = this.p;
        n1 n1Var = new n1(this.m, this.n, this.o, hVar2, this.q, hVar);
        n1Var.l = obj;
        return n1Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n1) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x007d, code lost:
    
        if (r6.emit(r7, r10) == r0) goto L26;
     */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0050  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x005d A[Catch: all -> 0x001c, TRY_LEAVE, TryCatch #0 {all -> 0x001c, blocks: (B:7:0x0016, B:18:0x0044, B:22:0x0055, B:24:0x005d, B:14:0x002c, B:17:0x003d), top: B:31:0x000a }] */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0080  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:25:0x007d -> B:8:0x0019). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r11) {
        /*
            r10 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r10.k
            androidx.compose.ui.platform.o1 r2 = r10.o
            r3 = 2
            r4 = 1
            android.content.ContentResolver r5 = r10.m
            if (r1 == 0) goto L30
            if (r1 == r4) goto L26
            if (r1 != r3) goto L1e
            kotlinx.coroutines.channels.c r1 = r10.j
            java.lang.Object r6 = r10.l
            kotlinx.coroutines.flow.j r6 = (kotlinx.coroutines.flow.InterfaceC5002j) r6
            androidx.glance.appwidget.protobuf.Z.e(r11)     // Catch: java.lang.Throwable -> L1c
        L19:
            r11 = r6
            r6 = r1
            goto L44
        L1c:
            r11 = move-exception
            goto L86
        L1e:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r0)
            throw r11
        L26:
            kotlinx.coroutines.channels.c r1 = r10.j
            java.lang.Object r6 = r10.l
            kotlinx.coroutines.flow.j r6 = (kotlinx.coroutines.flow.InterfaceC5002j) r6
            androidx.glance.appwidget.protobuf.Z.e(r11)     // Catch: java.lang.Throwable -> L1c
            goto L55
        L30:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            java.lang.Object r11 = r10.l
            kotlinx.coroutines.flow.j r11 = (kotlinx.coroutines.flow.InterfaceC5002j) r11
            android.net.Uri r1 = r10.n
            r6 = 0
            r5.registerContentObserver(r1, r6, r2)
            kotlinx.coroutines.channels.h r1 = r10.p     // Catch: java.lang.Throwable -> L1c
            kotlinx.coroutines.channels.c r6 = new kotlinx.coroutines.channels.c     // Catch: java.lang.Throwable -> L1c
            r6.<init>(r1)     // Catch: java.lang.Throwable -> L1c
        L44:
            r10.l = r11     // Catch: java.lang.Throwable -> L1c
            r10.j = r6     // Catch: java.lang.Throwable -> L1c
            r10.k = r4     // Catch: java.lang.Throwable -> L1c
            java.lang.Object r1 = r6.b(r10)     // Catch: java.lang.Throwable -> L1c
            if (r1 != r0) goto L51
            goto L7f
        L51:
            r9 = r6
            r6 = r11
            r11 = r1
            r1 = r9
        L55:
            java.lang.Boolean r11 = (java.lang.Boolean) r11     // Catch: java.lang.Throwable -> L1c
            boolean r11 = r11.booleanValue()     // Catch: java.lang.Throwable -> L1c
            if (r11 == 0) goto L80
            r1.c()     // Catch: java.lang.Throwable -> L1c
            android.content.Context r11 = r10.q     // Catch: java.lang.Throwable -> L1c
            android.content.ContentResolver r11 = r11.getContentResolver()     // Catch: java.lang.Throwable -> L1c
            java.lang.String r7 = "animator_duration_scale"
            r8 = 1065353216(0x3f800000, float:1.0)
            float r11 = android.provider.Settings.Global.getFloat(r11, r7, r8)     // Catch: java.lang.Throwable -> L1c
            java.lang.Float r7 = new java.lang.Float     // Catch: java.lang.Throwable -> L1c
            r7.<init>(r11)     // Catch: java.lang.Throwable -> L1c
            r10.l = r6     // Catch: java.lang.Throwable -> L1c
            r10.j = r1     // Catch: java.lang.Throwable -> L1c
            r10.k = r3     // Catch: java.lang.Throwable -> L1c
            java.lang.Object r11 = r6.emit(r7, r10)     // Catch: java.lang.Throwable -> L1c
            if (r11 != r0) goto L19
        L7f:
            return r0
        L80:
            r5.unregisterContentObserver(r2)
            kotlin.Unit r11 = kotlin.Unit.a
            return r11
        L86:
            r5.unregisterContentObserver(r2)
            throw r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.n1.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
