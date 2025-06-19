package com.google.android.gms.internal.mlkit_vision_common;

import android.app.NotificationManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.LayoutWeightElement;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.ZIndexElement;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class B4 {
    /* JADX WARN: Removed duplicated region for block: B:23:0x005b  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0079  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00c3  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00d6  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00d9  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00df  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00ec  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0102  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0104  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x010f  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0133  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x013b  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0179  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x01aa  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x01ae  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x01cf  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x01e3  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x0220  */
    /* JADX WARN: Removed duplicated region for block: B:98:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(final java.lang.String r22, final long r23, final long r25, final java.lang.String r27, androidx.compose.ui.q r28, androidx.compose.ui.text.L r29, androidx.compose.animation.core.K0 r30, com.quizlet.learn.viewmodel.k r31, androidx.compose.runtime.InterfaceC0806l r32, final int r33, final int r34) {
        /*
            Method dump skipped, instructions count: 564
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.B4.a(java.lang.String, long, long, java.lang.String, androidx.compose.ui.q, androidx.compose.ui.text.L, androidx.compose.animation.core.K0, com.quizlet.learn.viewmodel.k, androidx.compose.runtime.l, int, int):void");
    }

    public static final void b(com.quizlet.learn.ui.progress.g progressData, com.quizlet.learn.ui.progress.f progressBarType, Function0 onProgressAnimationFinish, androidx.compose.ui.q qVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        androidx.compose.animation.core.K0 k0;
        Intrinsics.checkNotNullParameter(progressData, "progressData");
        Intrinsics.checkNotNullParameter(progressBarType, "progressBarType");
        Intrinsics.checkNotNullParameter(onProgressAnimationFinish, "onProgressAnimationFinish");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-345303682);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(progressData) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(progressBarType) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(onProgressAnimationFinish) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.f(qVar) ? 2048 : 1024;
        }
        if ((i2 & 1171) == 1170 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(androidx.compose.foundation.layout.K0.c(qVar, 1.0f), "learn_progress_view");
            androidx.compose.foundation.layout.G0 g0B = androidx.compose.foundation.layout.E0.b(AbstractC0398m.a, androidx.compose.ui.b.k, c0814p, 48);
            int i3 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarG);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, g0B, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i3))) {
                android.support.v4.media.session.a.z(i3, c0814p, i3, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            com.quizlet.learn.ui.progress.i iVar = progressData.d;
            int iOrdinal = iVar.ordinal();
            if (iOrdinal == 0) {
                k0 = com.quizlet.learn.ui.progress.k.a;
            } else {
                if (iOrdinal != 1 && iOrdinal != 2 && iOrdinal != 3) {
                    throw new NoWhenBranchMatchedException();
                }
                k0 = com.quizlet.learn.ui.progress.j.a;
            }
            a(String.valueOf(progressData.a), ((C0861v) iVar.a.invoke(c0814p, 0)).a, ((C0861v) iVar.b.invoke(c0814p, 0)).a, "left_pill_label", null, null, k0, progressData.f, c0814p, 3072, 48);
            c0814p = c0814p;
            if (1.0f <= 0.0d) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", 1.0f, "; must be greater than zero").toString());
            }
            LayoutWeightElement layoutWeightElement = new LayoutWeightElement(1.0f > Float.MAX_VALUE ? Float.MAX_VALUE : 1.0f, true);
            com.quizlet.themes.m.g.u();
            com.quizlet.learn.ui.progress.e.b(progressData.a, progressData.b, progressData.c, progressBarType, AbstractC0382e.w(layoutWeightElement, com.quizlet.ui.resources.designsystem.generated.j.g, DefinitionKt.NO_Float_VALUE, 2).g(new ZIndexElement()), 0L, 0L, 0L, null, onProgressAnimationFinish, c0814p, ((i2 << 6) & 7168) | ((i2 << 21) & 1879048192));
            String strValueOf = String.valueOf(progressData.c);
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            a(strValueOf, ((com.quizlet.themes.b) c0814p.j(b)).b.b(), ((com.quizlet.themes.b) c0814p.j(b)).J0, "right_pill_label", null, null, null, null, c0814p, 3072, 240);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.i((Object) progressData, (Object) progressBarType, (Object) onProgressAnimationFinish, qVar, i, 25);
        }
    }

    public static void c(Context context) {
        Context applicationContext;
        PackageManager packageManager;
        ApplicationInfo applicationInfo;
        Bundle bundle;
        if (C4.e(context).getBoolean("proxy_notification_initialized", false)) {
            return;
        }
        try {
            applicationContext = context.getApplicationContext();
            packageManager = applicationContext.getPackageManager();
        } catch (PackageManager.NameNotFoundException unused) {
        }
        boolean z = (packageManager == null || (applicationInfo = packageManager.getApplicationInfo(applicationContext.getPackageName(), 128)) == null || (bundle = applicationInfo.metaData) == null || !bundle.containsKey("firebase_messaging_notification_delegation_enabled")) ? true : applicationInfo.metaData.getBoolean("firebase_messaging_notification_delegation_enabled");
        if (Build.VERSION.SDK_INT >= 29) {
            new com.google.firebase.messaging.r(context, z, new com.google.android.gms.tasks.f()).run();
        } else {
            S3.i(null);
        }
    }

    public static boolean d(Context context) {
        if (!(Build.VERSION.SDK_INT >= 29)) {
            Log.isLoggable("FirebaseMessaging", 3);
            return false;
        }
        if (Binder.getCallingUid() == context.getApplicationInfo().uid) {
            if (!"com.google.android.gms".equals(((NotificationManager) context.getSystemService(NotificationManager.class)).getNotificationDelegate())) {
                return false;
            }
            Log.isLoggable("FirebaseMessaging", 3);
            return true;
        }
        Log.e("FirebaseMessaging", "error retrieving notification delegate for package " + context.getPackageName());
        return false;
    }
}
