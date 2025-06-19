package androidx.emoji2.text;

import android.content.Context;
import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class f {
    public volatile Object a;
    public final Object b;
    public volatile Object c;

    public /* synthetic */ f(Object obj) {
        this.b = obj;
    }

    public boolean a() {
        Context context = (Context) this.b;
        try {
            return context.getPackageManager().getApplicationInfo(context.getPackageName(), 128).metaData.getBoolean("com.google.android.play.billingclient.enableBillingOverridesTesting", false);
        } catch (Exception e) {
            AbstractC3819n0.g("BillingClient", "Unable to retrieve metadata value for enableBillingOverridesTesting.", e);
            return false;
        }
    }

    public f(com.google.firebase.components.o oVar) {
        com.google.firebase.crashlytics.internal.breadcrumbs.b bVar = new com.google.firebase.crashlytics.internal.breadcrumbs.b();
        com.google.mlkit.common.sdkinternal.b bVar2 = new com.google.mlkit.common.sdkinternal.b(18);
        this.c = bVar;
        this.b = new ArrayList();
        this.a = bVar2;
        oVar.a(new com.google.firebase.crashlytics.a(this));
    }
}
