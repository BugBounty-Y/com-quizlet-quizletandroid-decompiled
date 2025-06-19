package androidx.glance.appwidget;

import android.appwidget.AppWidgetManager;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.widget.RemoteViews;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3225o7;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.widgets.AbstractC4769b;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.Unit;
import kotlinx.coroutines.C5027k0;

/* renamed from: androidx.glance.appwidget.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1182m {
    public final String a;
    public final AtomicBoolean b;
    public final kotlinx.coroutines.channels.h c;
    public final AbstractC4769b d;
    public final C1162c e;
    public final androidx.glance.state.a f;
    public final J0 g;
    public final boolean h;
    public final InterfaceC0773a0 i;
    public final InterfaceC0773a0 j;
    public Object k;
    public final C5027k0 l;
    public final kotlinx.coroutines.flow.s0 m;

    public C1182m(AbstractC4769b abstractC4769b, C1162c c1162c, Bundle bundle, int i) {
        bundle = (i & 4) != 0 ? null : bundle;
        androidx.glance.state.f fVar = androidx.glance.state.f.a;
        ((com.quizlet.quizletandroid.ui.widgets.y) abstractC4769b).getClass();
        H0 h0 = com.quizlet.quizletandroid.ui.widgets.y.d;
        this.a = AbstractC3225o7.e(c1162c.a);
        this.b = new AtomicBoolean(true);
        this.c = D1.a(SubsamplingScaleImageView.TILE_SIZE_AUTO, 6, null);
        this.d = abstractC4769b;
        this.e = c1162c;
        this.f = fVar;
        this.g = h0;
        this.h = true;
        int i2 = c1162c.a;
        if (Integer.MIN_VALUE <= i2 && i2 < -1) {
            throw new IllegalArgumentException("If the AppWidgetSession is not created for a bound widget, you must provide a lambda action receiver");
        }
        androidx.compose.runtime.V v = androidx.compose.runtime.V.c;
        this.i = C0776c.y(null, v);
        this.j = C0776c.y(bundle, v);
        this.k = kotlin.collections.V.c();
        this.l = kotlinx.coroutines.E.d();
        this.m = kotlinx.coroutines.flow.e0.c(null);
    }

    public final void a(Context context, Throwable th) throws Throwable {
        Log.e("GlanceAppWidget", "Error in Glance App Widget", th);
        if (!this.h) {
            throw th;
        }
        int i = this.e.a;
        this.d.getClass();
        AppWidgetManager.getInstance(context).updateAppWidget(i, new RemoteViews(context.getPackageName(), R.layout.glance_error_layout));
    }

    /* JADX WARN: Can't wrap try/catch for region: R(12:0|2|(2:4|(1:6)(1:7))(0)|8|(1:(1:(4:18|42|59|60)(1:(2:15|16)(3:17|54|55)))(1:19))(2:20|(2:22|23)(3:24|(1:27)|58))|28|63|29|30|31|(4:33|(1:35)|38|39)(3:43|44|45)|(3:(0)|(0)|(0))) */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00d7, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00ea, code lost:
    
        if (r15.b(r5) == r6) goto L58;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x010a, code lost:
    
        r7.a(r12, r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x010d, code lost:
    
        r5.j = null;
        r5.k = null;
        r5.l = null;
        r5.o = 4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x0119, code lost:
    
        if (r15.b(r5) != r6) goto L42;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x011c, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x011d, code lost:
    
        r5.j = r0;
        r5.k = null;
        r5.l = null;
        r5.o = 5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x0129, code lost:
    
        if (r15.b(r5) != r6) goto L54;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0130, code lost:
    
        r5.j = null;
        r5.k = null;
        r5.l = null;
        r5.o = 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x013c, code lost:
    
        if (r15.b(r5) != r6) goto L42;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(android.content.Context r19, androidx.glance.m r20, kotlin.coroutines.jvm.internal.c r21) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 322
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.C1182m.b(android.content.Context, androidx.glance.m, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r0v4, types: [java.lang.Object, java.util.Map] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(android.content.Context r7, java.lang.Object r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 400
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.C1182m.c(android.content.Context, java.lang.Object, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:29:0x008c, code lost:
    
        if (r5.c(r2, r10, r0) == r1) goto L30;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0069  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0077 A[Catch: ClosedReceiveChannelException -> 0x008f, TRY_LEAVE, TryCatch #0 {ClosedReceiveChannelException -> 0x008f, blocks: (B:13:0x002e, B:22:0x0058, B:26:0x006f, B:28:0x0077, B:18:0x0046, B:21:0x004d), top: B:34:0x0020 }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r9v4, types: [kotlin.jvm.functions.Function1] */
    /* JADX WARN: Type inference failed for: r9v6, types: [kotlin.jvm.functions.Function1] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:29:0x008c -> B:14:0x0031). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(android.content.Context r8, androidx.activity.compose.g r9, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            r7 = this;
            boolean r0 = r10 instanceof androidx.glance.session.C1232j
            if (r0 == 0) goto L13
            r0 = r10
            androidx.glance.session.j r0 = (androidx.glance.session.C1232j) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.p = r1
            goto L18
        L13:
            androidx.glance.session.j r0 = new androidx.glance.session.j
            r0.<init>(r7, r10)
        L18:
            java.lang.Object r10 = r0.n
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.p
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L4a
            if (r2 == r4) goto L3e
            if (r2 != r3) goto L36
            kotlinx.coroutines.channels.c r8 = r0.m
            kotlin.jvm.functions.Function1 r9 = r0.l
            android.content.Context r2 = r0.k
            androidx.glance.appwidget.m r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
        L31:
            r10 = r2
            r2 = r8
            r8 = r10
            r10 = r5
            goto L58
        L36:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L3e:
            kotlinx.coroutines.channels.c r8 = r0.m
            kotlin.jvm.functions.Function1 r9 = r0.l
            android.content.Context r2 = r0.k
            androidx.glance.appwidget.m r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            goto L6f
        L4a:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            kotlinx.coroutines.channels.h r10 = r7.c     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            r10.getClass()     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            kotlinx.coroutines.channels.c r2 = new kotlinx.coroutines.channels.c     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            r2.<init>(r10)     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            r10 = r7
        L58:
            r0.j = r10     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            r0.k = r8     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            r0.l = r9     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            r0.m = r2     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            r0.p = r4     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            java.lang.Object r5 = r2.b(r0)     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            if (r5 != r1) goto L69
            goto L8e
        L69:
            r6 = r2
            r2 = r8
            r8 = r6
            r6 = r5
            r5 = r10
            r10 = r6
        L6f:
            java.lang.Boolean r10 = (java.lang.Boolean) r10     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            boolean r10 = r10.booleanValue()     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            if (r10 == 0) goto L8f
            java.lang.Object r10 = r8.c()     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            r9.invoke(r10)     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            r0.j = r5     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            r0.k = r2     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            r0.l = r9     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            r0.m = r8     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            r0.p = r3     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            java.lang.Object r10 = r5.c(r2, r10, r0)     // Catch: kotlinx.coroutines.channels.ClosedReceiveChannelException -> L8f
            if (r10 != r1) goto L31
        L8e:
            return r1
        L8f:
            kotlin.Unit r8 = kotlin.Unit.a
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.C1182m.d(android.content.Context, androidx.activity.compose.g, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final Object e(Object obj, kotlin.coroutines.jvm.internal.c cVar) {
        Object objS = this.c.s(obj, cVar);
        return objS == kotlin.coroutines.intrinsics.a.a ? objS : Unit.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object f(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof androidx.glance.appwidget.C1180l
            if (r0 == 0) goto L13
            r0 = r6
            androidx.glance.appwidget.l r0 = (androidx.glance.appwidget.C1180l) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.glance.appwidget.l r0 = new androidx.glance.appwidget.l
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            androidx.glance.appwidget.g r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4c
        L29:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            androidx.glance.appwidget.g r6 = new androidx.glance.appwidget.g
            kotlinx.coroutines.k0 r2 = r5.l
            kotlinx.coroutines.k0 r4 = new kotlinx.coroutines.k0
            r4.<init>(r2)
            r6.<init>(r4)
            r0.j = r6
            r0.m = r3
            java.lang.Object r0 = r5.e(r6, r0)
            if (r0 != r1) goto L4b
            return r1
        L4b:
            r0 = r6
        L4c:
            kotlinx.coroutines.k0 r6 = r0.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.C1182m.f(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
