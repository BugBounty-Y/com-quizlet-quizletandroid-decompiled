package com.appsflyer.internal;

import android.content.Context;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.HashMap;
import java.util.Map;
import java.util.Observable;
import java.util.Observer;

/* loaded from: classes.dex */
public abstract class AFj1qSDK extends Observable {
    public final String areAllFieldsValid;
    long component1;
    public final String component2;
    final Runnable getRevenue;
    public final Map<String, Object> AFAdRevenueData = new HashMap();
    public AFa1ySDK component4 = AFa1ySDK.NOT_STARTED;

    /* renamed from: com.appsflyer.internal.AFj1qSDK$5, reason: invalid class name */
    public class AnonymousClass5 implements Observer {
        public AnonymousClass5() {
        }

        @Override // java.util.Observer
        public final void update(Observable observable, Object obj) {
            AFj1qSDK.this.getRevenue.run();
        }
    }

    public enum AFa1ySDK {
        NOT_STARTED,
        STARTED,
        FINISHED
    }

    public AFj1qSDK(String str, String str2, Runnable runnable) {
        this.getRevenue = runnable;
        this.component2 = str2;
        this.areAllFieldsValid = str;
    }

    public final void getMediationNetwork() {
        this.AFAdRevenueData.put("source", this.component2);
        this.AFAdRevenueData.put(DBUserFields.Names.USER_UPGRADE_TYPE, this.areAllFieldsValid);
        getMonetizationNetwork();
        this.component4 = AFa1ySDK.FINISHED;
        setChanged();
        notifyObservers();
    }

    public void getMonetizationNetwork() {
        this.AFAdRevenueData.put("latency", Long.valueOf(System.currentTimeMillis() - this.component1));
    }

    public abstract void getRevenue(Context context);
}
