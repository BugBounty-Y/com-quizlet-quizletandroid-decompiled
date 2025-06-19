package com.appsflyer.internal;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class AFb1kSDK extends AFb1tSDK<String> {
    public AFb1kSDK(Context context, Executor executor) {
        super(context, executor, "com.facebook.katana.provider.AttributionIdProvider", "E3F9E1E0CF99D0E56A055BA65E241B3399F7CEA524326B0CDD6EC1327ED0FDC1");
    }

    /* JADX INFO: Access modifiers changed from: private */
    @Override // com.appsflyer.internal.AFb1tSDK
    /* renamed from: AFAdRevenueData, reason: merged with bridge method [inline-methods] */
    public String getCurrencyIso4217Code() throws Throwable {
        Cursor cursor = null;
        try {
            ContentResolver contentResolver = this.getCurrencyIso4217Code.getContentResolver();
            StringBuilder sb = new StringBuilder("content://");
            sb.append(this.getMediationNetwork);
            Cursor cursorQuery = contentResolver.query(Uri.parse(sb.toString()), new String[]{"aid"}, null, null, null);
            if (cursorQuery != null) {
                try {
                    if (cursorQuery.moveToFirst()) {
                        String string = cursorQuery.getString(cursorQuery.getColumnIndexOrThrow("aid"));
                        cursorQuery.close();
                        return string;
                    }
                } catch (Throwable th) {
                    th = th;
                    cursor = cursorQuery;
                    if (cursor != null) {
                        cursor.close();
                    }
                    throw th;
                }
            }
            if (cursorQuery != null) {
                cursorQuery.close();
            }
            return null;
        } catch (Throwable th2) {
            th = th2;
        }
    }

    @Override // com.appsflyer.internal.AFb1tSDK
    public final /* synthetic */ String getMonetizationNetwork() {
        this.getRevenue.execute(this.AFAdRevenueData);
        return (String) super.getMonetizationNetwork();
    }

    public final String getRevenue() {
        this.getRevenue.execute(this.AFAdRevenueData);
        return (String) super.getMonetizationNetwork();
    }
}
