package com.appsflyer.internal;

import android.content.ContentResolver;
import android.content.Context;
import android.content.pm.PackageItemInfo;
import android.database.Cursor;
import android.net.Uri;
import com.appsflyer.AFLogger;
import com.appsflyer.internal.AFj1qSDK;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes.dex */
public final class AFj1tSDK extends AFi1bSDK {
    private final AFc1dSDK getMediationNetwork;

    public AFj1tSDK(Runnable runnable, AFc1dSDK aFc1dSDK) {
        super("store", "samsung", runnable);
        this.getMediationNetwork = aFc1dSDK;
    }

    @Override // com.appsflyer.internal.AFj1qSDK
    public final void getRevenue(Context context) {
        AFb1tSDK<Map<String, Object>> aFb1tSDK = new AFb1tSDK<Map<String, Object>>(context, this.getMediationNetwork.getMonetizationNetwork(), "com.sec.android.app.samsungapps.referrer", "FBA3AF4E7757D9016E953FB3EE4671CA2BD9AF725F9A53D52ED4A38EAAA08901") { // from class: com.appsflyer.internal.AFj1tSDK.2
            /* JADX INFO: Access modifiers changed from: private */
            @Override // com.appsflyer.internal.AFb1tSDK
            /* renamed from: AFAdRevenueData, reason: merged with bridge method [inline-methods] */
            public Map<String, Object> getCurrencyIso4217Code() {
                String string;
                Cursor cursorQuery = null;
                try {
                    try {
                        ContentResolver contentResolver = this.getCurrencyIso4217Code.getContentResolver();
                        StringBuilder sb = new StringBuilder("content://");
                        sb.append(this.getMediationNetwork);
                        cursorQuery = contentResolver.query(Uri.parse(sb.toString()), null, null, null, null);
                        if (cursorQuery == null) {
                            AFj1tSDK.this.AFAdRevenueData.put("response", "SERVICE_UNAVAILABLE");
                        } else if (cursorQuery.moveToFirst()) {
                            AFj1tSDK.this.AFAdRevenueData.put("response", "OK");
                            E_("referrer", AFj1tSDK.this.AFAdRevenueData, cursorQuery);
                            D_("click_ts", AFj1tSDK.this.AFAdRevenueData, cursorQuery);
                            D_("install_begin_ts", AFj1tSDK.this.AFAdRevenueData, cursorQuery);
                            D_("install_end_ts", AFj1tSDK.this.AFAdRevenueData, cursorQuery);
                            E_("organic_keywords", AFj1tSDK.this.AFAdRevenueData, cursorQuery);
                            E_("attr_type", AFj1tSDK.this.AFAdRevenueData, cursorQuery);
                            HashMap map = new HashMap();
                            int columnIndex = cursorQuery.getColumnIndex("instant");
                            if (columnIndex != -1 && (string = cursorQuery.getString(columnIndex)) != null) {
                                map.put("instant", Boolean.valueOf(Boolean.parseBoolean(string)));
                            }
                            D_("click_server_ts", map, cursorQuery);
                            D_("install_begin_server_ts", map, cursorQuery);
                            E_("install_version", map, cursorQuery);
                            if (!map.isEmpty()) {
                                AFj1tSDK.this.AFAdRevenueData.put("custom", map);
                            }
                        } else {
                            AFj1tSDK.this.AFAdRevenueData.put("response", "FEATURE_NOT_SUPPORTED");
                        }
                    } catch (Exception e) {
                        AFj1tSDK.this.AFAdRevenueData.put("response", "FEATURE_NOT_SUPPORTED");
                        AFLogger.afErrorLog(e.getMessage(), e, false, true);
                        if (0 != 0) {
                        }
                    }
                    if (cursorQuery != null) {
                        cursorQuery.close();
                    }
                    String str = ((PackageItemInfo) this.getCurrencyIso4217Code.getPackageManager().resolveContentProvider(this.getMediationNetwork, 128)).packageName;
                    AFj1tSDK.this.AFAdRevenueData.put("api_ver", Long.valueOf(AFj1iSDK.AFAdRevenueData(this.getCurrencyIso4217Code, str)));
                    AFj1tSDK.this.AFAdRevenueData.put("api_ver_name", AFj1iSDK.getMediationNetwork(this.getCurrencyIso4217Code, str));
                    AFj1tSDK.this.getMediationNetwork();
                    return AFj1tSDK.this.AFAdRevenueData;
                } catch (Throwable th) {
                    if (0 != 0) {
                        cursorQuery.close();
                    }
                    throw th;
                }
            }

            private static void D_(String str, Map<String, Object> map, Cursor cursor) {
                int columnIndex = cursor.getColumnIndex(str);
                if (columnIndex == -1) {
                    return;
                }
                long j = cursor.getLong(columnIndex);
                if (j == 0) {
                    return;
                }
                map.put(str, Long.valueOf(j));
            }

            private static void E_(String str, Map<String, Object> map, Cursor cursor) {
                String string;
                int columnIndex = cursor.getColumnIndex(str);
                if (columnIndex == -1 || (string = cursor.getString(columnIndex)) == null) {
                    return;
                }
                map.put(str, string);
            }
        };
        AFc1qSDK aFc1qSDKComponent2 = this.getMediationNetwork.component2();
        if (((Integer) AFa1tSDK.getMonetizationNetwork(new Object[]{aFc1qSDKComponent2, Boolean.FALSE}, -1175980247, 1175980268, (int) System.currentTimeMillis())).intValue() > 0 || !aFb1tSDK.getMediationNetwork()) {
            return;
        }
        aFb1tSDK.getRevenue.execute(aFb1tSDK.AFAdRevenueData);
        this.component1 = System.currentTimeMillis();
        this.component4 = AFj1qSDK.AFa1ySDK.STARTED;
        addObserver(new AFj1qSDK.AnonymousClass5());
    }
}
