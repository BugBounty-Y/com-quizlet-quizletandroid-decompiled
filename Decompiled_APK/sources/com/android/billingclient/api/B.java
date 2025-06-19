package com.android.billingclient.api;

import android.content.Intent;
import android.os.ResultReceiver;
import androidx.activity.result.ActivityResult;
import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import com.google.android.gms.measurement.internal.G0;
import com.google.mlkit.vision.documentscanner.internal.GmsDocumentScanningDelegateActivity;

/* loaded from: classes.dex */
public final /* synthetic */ class B implements androidx.activity.result.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.activity.s b;

    public /* synthetic */ B(androidx.activity.s sVar, int i) {
        this.a = i;
        this.b = sVar;
    }

    @Override // androidx.activity.result.a
    public final void a(Object obj) {
        ActivityResult activityResult = (ActivityResult) obj;
        switch (this.a) {
            case 0:
                ProxyBillingActivityV2 proxyBillingActivityV2 = (ProxyBillingActivityV2) this.b;
                proxyBillingActivityV2.getClass();
                Intent intent = activityResult.b;
                int i = AbstractC3819n0.c("ProxyBillingActivityV2", intent).a;
                ResultReceiver resultReceiver = proxyBillingActivityV2.c;
                if (resultReceiver != null) {
                    resultReceiver.send(i, intent == null ? null : intent.getExtras());
                }
                int i2 = activityResult.a;
                if (i2 != -1 || i != 0) {
                    AbstractC3819n0.f("ProxyBillingActivityV2", "Alternative billing only dialog finished with resultCode " + i2 + " and billing's responseCode: " + i);
                }
                proxyBillingActivityV2.finish();
                break;
            case 1:
                ProxyBillingActivityV2 proxyBillingActivityV22 = (ProxyBillingActivityV2) this.b;
                proxyBillingActivityV22.getClass();
                Intent intent2 = activityResult.b;
                int i3 = AbstractC3819n0.c("ProxyBillingActivityV2", intent2).a;
                ResultReceiver resultReceiver2 = proxyBillingActivityV22.d;
                if (resultReceiver2 != null) {
                    resultReceiver2.send(i3, intent2 == null ? null : intent2.getExtras());
                }
                int i4 = activityResult.a;
                if (i4 != -1 || i3 != 0) {
                    AbstractC3819n0.f("ProxyBillingActivityV2", "External offer dialog finished with resultCode: " + i4 + " and billing's responseCode: " + i3);
                }
                proxyBillingActivityV22.finish();
                break;
            default:
                GmsDocumentScanningDelegateActivity gmsDocumentScanningDelegateActivity = (GmsDocumentScanningDelegateActivity) this.b;
                com.google.firebase.crashlytics.internal.settings.b bVar = new com.google.firebase.crashlytics.internal.settings.b(gmsDocumentScanningDelegateActivity.getApplicationContext(), 2);
                int i5 = activityResult.a;
                com.google.android.gms.tasks.f fVar = new com.google.android.gms.tasks.f();
                com.google.mlkit.common.sdkinternal.k.a.execute(new G0(i5, 2, bVar, activityResult.b, fVar));
                com.google.mlkit.vision.documentscanner.internal.c cVar = new com.google.mlkit.vision.documentscanner.internal.c(gmsDocumentScanningDelegateActivity, 0);
                com.google.android.gms.tasks.m mVar = fVar.a;
                mVar.getClass();
                mVar.d(com.google.android.gms.tasks.g.a, cVar);
                mVar.o(new com.quizlet.data.repository.school.membership.a(gmsDocumentScanningDelegateActivity, 26));
                break;
        }
    }
}
