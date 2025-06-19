package androidx.glance.appwidget;

import android.appwidget.AppWidgetManager;
import android.content.Context;
import androidx.datastore.core.InterfaceC1076h;
import com.google.android.gms.internal.mlkit_vision_barcode.O6;
import com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class X {
    public static final P d = new P();
    public static final androidx.datastore.b e = O6.a("GlanceAppWidgetManager", null, 14);
    public static InterfaceC1076h f;
    public static final androidx.datastore.preferences.core.f g;
    public final Context a;
    public final AppWidgetManager b;
    public final kotlin.u c = kotlin.l.b(new androidx.compose.ui.input.nestedscroll.b(this, 22));

    static {
        Intrinsics.checkNotNullParameter("list::Providers", "name");
        g = new androidx.datastore.preferences.core.f("list::Providers");
    }

    public X(@NotNull Context context) {
        this.a = context;
        this.b = AppWidgetManager.getInstance(context);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r9v6, types: [java.lang.Object, java.util.Map] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.io.Serializable a(java.lang.Class r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.IllegalAccessException, java.lang.InstantiationException, java.lang.IllegalArgumentException, java.lang.reflect.InvocationTargetException {
        /*
            r7 = this;
            boolean r0 = r9 instanceof androidx.glance.appwidget.U
            if (r0 == 0) goto L13
            r0 = r9
            androidx.glance.appwidget.U r0 = (androidx.glance.appwidget.U) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.glance.appwidget.U r0 = new androidx.glance.appwidget.U
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            java.lang.Class r8 = r0.k
            androidx.glance.appwidget.X r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L44
        L2b:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r0.j = r7
            r0.k = r8
            r0.n = r3
            java.lang.Object r9 = r7.b(r0)
            if (r9 != r1) goto L43
            return r1
        L43:
            r0 = r7
        L44:
            androidx.glance.appwidget.Q r9 = (androidx.glance.appwidget.Q) r9
            java.lang.String r8 = r8.getCanonicalName()
            if (r8 == 0) goto L90
            java.lang.Object r9 = r9.b
            java.lang.Object r8 = r9.get(r8)
            java.util.List r8 = (java.util.List) r8
            if (r8 != 0) goto L59
            kotlin.collections.K r8 = kotlin.collections.K.a
            return r8
        L59:
            java.util.ArrayList r9 = new java.util.ArrayList
            r9.<init>()
            java.util.Iterator r8 = r8.iterator()
        L62:
            boolean r1 = r8.hasNext()
            if (r1 == 0) goto L8f
            java.lang.Object r1 = r8.next()
            android.content.ComponentName r1 = (android.content.ComponentName) r1
            android.appwidget.AppWidgetManager r2 = r0.b
            int[] r1 = r2.getAppWidgetIds(r1)
            java.util.ArrayList r2 = new java.util.ArrayList
            int r3 = r1.length
            r2.<init>(r3)
            int r3 = r1.length
            r4 = 0
        L7c:
            if (r4 >= r3) goto L8b
            r5 = r1[r4]
            androidx.glance.appwidget.c r6 = new androidx.glance.appwidget.c
            r6.<init>(r5)
            r2.add(r6)
            int r4 = r4 + 1
            goto L7c
        L8b:
            kotlin.collections.G.u(r9, r2)
            goto L62
        L8f:
            return r9
        L90:
            java.lang.IllegalArgumentException r8 = new java.lang.IllegalArgumentException
            java.lang.String r9 = "no canonical provider name"
            r8.<init>(r9)
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.X.a(java.lang.Class, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:48:0x0106  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(kotlin.coroutines.jvm.internal.c r12) throws java.lang.IllegalAccessException, java.lang.InstantiationException, java.lang.IllegalArgumentException, java.lang.reflect.InvocationTargetException {
        /*
            Method dump skipped, instructions count: 398
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.glance.appwidget.X.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final Object c(QuizletWidgetReceiver quizletWidgetReceiver, com.quizlet.quizletandroid.ui.widgets.y yVar, C1165d0 c1165d0) {
        d.getClass();
        String canonicalName = quizletWidgetReceiver.getClass().getCanonicalName();
        if (canonicalName == null) {
            throw new IllegalArgumentException("no receiver name");
        }
        String canonicalName2 = yVar.getClass().getCanonicalName();
        if (canonicalName2 == null) {
            throw new IllegalArgumentException("no provider name");
        }
        Object objA = ((InterfaceC1076h) this.c.getValue()).a(new W(canonicalName, canonicalName2, null), c1165d0);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : Unit.a;
    }
}
