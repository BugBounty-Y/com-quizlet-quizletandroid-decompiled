package com.google.firebase.messaging;

import android.app.NotificationManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Binder;
import android.util.Log;
import android.view.ViewPropertyAnimator;
import android.view.animation.DecelerateInterpolator;
import com.google.android.gms.internal.mlkit_vision_common.C4;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.quizlet.quizletandroid.ui.setcreation.managers.CardVisibilityFABBehavior;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final /* synthetic */ class r implements Runnable {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ r(Context context, boolean z, com.google.android.gms.tasks.f fVar) {
        this.c = context;
        this.b = z;
        this.d = fVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Context context = (Context) this.c;
                com.google.android.gms.tasks.f fVar = (com.google.android.gms.tasks.f) this.d;
                try {
                    if (Binder.getCallingUid() == context.getApplicationInfo().uid) {
                        SharedPreferences.Editor editorEdit = C4.e(context).edit();
                        editorEdit.putBoolean("proxy_notification_initialized", true);
                        editorEdit.apply();
                        NotificationManager notificationManager = (NotificationManager) context.getSystemService(NotificationManager.class);
                        if (this.b) {
                            notificationManager.setNotificationDelegate("com.google.android.gms");
                        } else if ("com.google.android.gms".equals(notificationManager.getNotificationDelegate())) {
                            notificationManager.setNotificationDelegate(null);
                        }
                    } else {
                        Log.e("FirebaseMessaging", "error configuring notification delegate for package " + context.getPackageName());
                    }
                    return;
                } finally {
                    fVar.d(null);
                }
            default:
                CardVisibilityFABBehavior cardVisibilityFABBehavior = (CardVisibilityFABBehavior) this.c;
                cardVisibilityFABBehavior.getClass();
                FloatingActionButton floatingActionButton = (FloatingActionButton) this.d;
                ViewPropertyAnimator viewPropertyAnimatorAnimate = floatingActionButton.animate();
                boolean z = this.b;
                float f = DefinitionKt.NO_Float_VALUE;
                ViewPropertyAnimator viewPropertyAnimatorScaleX = viewPropertyAnimatorAnimate.scaleX(z ? 1.0f : 0.0f);
                if (z) {
                    f = 1.0f;
                }
                cardVisibilityFABBehavior.a = viewPropertyAnimatorScaleX.scaleY(f).setDuration(z ? 201L : 200L).setInterpolator(new DecelerateInterpolator()).setListener(new com.quizlet.quizletandroid.ui.setcreation.managers.d(cardVisibilityFABBehavior, floatingActionButton, z));
                return;
        }
    }

    public /* synthetic */ r(CardVisibilityFABBehavior cardVisibilityFABBehavior, FloatingActionButton floatingActionButton, boolean z) {
        this.c = cardVisibilityFABBehavior;
        this.d = floatingActionButton;
        this.b = z;
    }
}
