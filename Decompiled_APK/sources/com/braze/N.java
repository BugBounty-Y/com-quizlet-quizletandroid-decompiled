package com.braze;

import android.app.Activity;
import com.braze.managers.C1500m;
import com.braze.ui.inappmessage.BrazeInAppMessageManager;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class N implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Activity b;

    public /* synthetic */ N(int i, Activity activity) {
        this.a = i;
        this.b = activity;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeActivityLifecycleCallbackListener.onActivityStopped$lambda$5(this.b);
            case 1:
                return BrazeActivityLifecycleCallbackListener.onActivityPaused$lambda$8(this.b);
            case 2:
                return BrazeActivityLifecycleCallbackListener.onActivityStarted$lambda$4(this.b);
            case 3:
                return BrazeActivityLifecycleCallbackListener.onActivityCreated$lambda$10(this.b);
            case 4:
                return BrazeActivityLifecycleCallbackListener.onActivityResumed$lambda$7(this.b);
            case 5:
                return C1500m.b(this.b);
            case 6:
                return C1500m.d(this.b);
            case 7:
                return BrazeInAppMessageManager.unregisterInAppMessageManager$lambda$19(this.b);
            case 8:
                return BrazeInAppMessageManager.unregisterInAppMessageManager$lambda$21(this.b);
            case 9:
                return BrazeInAppMessageManager.registerInAppMessageManager$lambda$10(this.b);
            default:
                Activity activity = this.b;
                if (activity != null) {
                    activity.finish();
                }
                return Unit.a;
        }
    }
}
