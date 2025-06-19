package com.quizlet.quizletandroid.ui.startpage.nav2.pushnotification;

import android.content.DialogInterface;
import androidx.fragment.app.AbstractC1136h0;
import com.quizlet.data.repository.classfolder.e;
import com.quizlet.eventlogger.features.pushnotifications.PushNotificationLogger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements DialogInterface.OnDismissListener {
    public final /* synthetic */ e a;
    public final /* synthetic */ AbstractC1136h0 b;

    public /* synthetic */ a(e eVar, AbstractC1136h0 abstractC1136h0) {
        this.a = eVar;
        this.b = abstractC1136h0;
    }

    @Override // android.content.DialogInterface.OnDismissListener
    public final void onDismiss(DialogInterface dialogInterface) {
        Intrinsics.d(dialogInterface);
        e eVar = this.a;
        AbstractC1136h0 fragmentManager = this.b;
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        Intrinsics.checkNotNullParameter(dialogInterface, "dialogInterface");
        if (fragmentManager.K) {
            return;
        }
        PushNotificationLogger pushNotificationLogger = (PushNotificationLogger) eVar.c;
        pushNotificationLogger.d();
        dialogInterface.dismiss();
        pushNotificationLogger.c();
        androidx.activity.result.b bVar = (androidx.activity.result.b) eVar.d;
        if (bVar != null) {
            bVar.a("android.permission.POST_NOTIFICATIONS");
        } else {
            Intrinsics.m("requestPermissionLauncher");
            throw null;
        }
    }
}
