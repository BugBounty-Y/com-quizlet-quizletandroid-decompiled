package com.quizlet.quizletandroid.ui.widgets;

import android.content.Context;
import android.os.Build;
import androidx.glance.appwidget.C1162c;
import androidx.glance.appwidget.L0;
import androidx.glance.appwidget.M;
import androidx.glance.appwidget.M0;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.Unit;

/* renamed from: com.quizlet.quizletandroid.ui.widgets.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC4769b {
    public final androidx.glance.session.p a = androidx.glance.session.q.a;
    public final androidx.glance.state.h b = androidx.glance.state.h.a;

    public static Object c(AbstractC4769b abstractC4769b, Context context, int i, kotlin.coroutines.jvm.internal.c cVar) throws Throwable {
        abstractC4769b.getClass();
        AtomicBoolean atomicBoolean = L0.a;
        if (Build.VERSION.SDK_INT >= 29 && L0.a.get()) {
            M0.a.a("GlanceAppWidget::update", 0);
        }
        Object objA = abstractC4769b.a.a(new M(context, new C1162c(i), abstractC4769b, null), cVar);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : Unit.a;
    }

    /* JADX WARN: Code restructure failed: missing block: B:31:0x009e, code lost:
    
        if (r2.a(r9, r10, r8, r0) == r1) goto L56;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x00c7, code lost:
    
        if (r2.a(r9, r10, r8, r0) == r1) goto L56;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x00fb, code lost:
    
        if (r2.a(r9, r10, r8, r0) == r1) goto L56;
     */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x008d  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00b6  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x00ea  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(android.content.Context r8, int r9, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 276
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.widgets.AbstractC4769b.a(android.content.Context, int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public abstract void b(InterfaceC4768a interfaceC4768a, kotlin.coroutines.jvm.internal.c cVar);
}
