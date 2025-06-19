package com.quizlet.quizletandroid.receivers;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import com.google.android.gms.analytics.CampaignTrackingReceiver;
import com.quizlet.quizletandroid.managers.e;
import com.quizlet.quizletandroid.managers.f;
import timber.log.c;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements f {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Context b;
    public final /* synthetic */ Intent c;
    public final /* synthetic */ Object d;

    public /* synthetic */ a(CoppaCompliantAdwordsConversionTrackingInstallReceiver coppaCompliantAdwordsConversionTrackingInstallReceiver, Context context, Intent intent) {
        this.d = coppaCompliantAdwordsConversionTrackingInstallReceiver;
        this.b = context;
        this.c = intent;
    }

    @Override // com.quizlet.quizletandroid.managers.f
    public final void a(e eVar) {
        Intent intent = this.c;
        Context context = this.b;
        Object obj = this.d;
        switch (this.a) {
            case 0:
                CoppaCompliantAdwordsConversionTrackingInstallReceiver.a((CoppaCompliantAdwordsConversionTrackingInstallReceiver) obj, context, intent, eVar);
                break;
            default:
                BroadcastReceiver.PendingResult pendingResult = (BroadcastReceiver.PendingResult) obj;
                int i = CoppaCompliantCampaignTrackingReceiver.d;
                Object[] objArr = {eVar.name()};
                timber.log.a aVar = c.a;
                aVar.g("Compliance state: %s", objArr);
                if (eVar != e.b) {
                    intent.setComponent(new ComponentName(context, (Class<?>) CampaignTrackingReceiver.class));
                    context.sendBroadcast(intent);
                }
                try {
                    pendingResult.finish();
                    break;
                } catch (IllegalStateException e) {
                    aVar.f(e, "Failed to finish pending result", new Object[0]);
                }
        }
    }

    public /* synthetic */ a(CoppaCompliantCampaignTrackingReceiver coppaCompliantCampaignTrackingReceiver, Context context, Intent intent, BroadcastReceiver.PendingResult pendingResult) {
        this.b = context;
        this.c = intent;
        this.d = pendingResult;
    }
}
