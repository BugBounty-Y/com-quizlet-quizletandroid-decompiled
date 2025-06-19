package org.prebid.mobile.rendering.utils.helpers;

import android.content.Context;
import android.os.AsyncTask;
import android.util.Log;
import com.google.android.gms.ads.identifier.a;
import com.google.android.gms.ads.identifier.b;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.c;
import java.lang.ref.WeakReference;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.sdk.PrebidContextHolder;

/* loaded from: classes3.dex */
public abstract class AdvertisingIdManager {
    public static long a;
    public static volatile AdvertisingId b;

    public static class AdvertisingId {
        public String a;
        public boolean b;
    }

    public static class FetchTask extends AsyncTask<Void, Void, AdvertisingId> {
        public final WeakReference a = new WeakReference(PrebidContextHolder.a());

        public final AdvertisingId a() {
            Context context = (Context) this.a.get();
            if (isCancelled() || context == null) {
                return null;
            }
            try {
                long jCurrentTimeMillis = System.currentTimeMillis();
                if (GoogleApiAvailability.d.c(context, c.a) != 0) {
                    return null;
                }
                a aVarA = b.a(context);
                LogUtil.e(3, "AdvertisingIdManager", "Advertising id fetching took " + (System.currentTimeMillis() - jCurrentTimeMillis) + " ms");
                String str = aVarA.a;
                boolean z = aVarA.b;
                AdvertisingId advertisingId = new AdvertisingId();
                advertisingId.a = str;
                advertisingId.b = z;
                return advertisingId;
            } catch (Throwable th) {
                LogUtil.b("AdvertisingIdManager", "Failed to get advertising id: " + Log.getStackTraceString(th));
                return null;
            }
        }

        @Override // android.os.AsyncTask
        public final /* bridge */ /* synthetic */ AdvertisingId doInBackground(Void[] voidArr) {
            return a();
        }

        @Override // android.os.AsyncTask
        public final void onPostExecute(AdvertisingId advertisingId) {
            AdvertisingIdManager.b = advertisingId;
        }
    }
}
