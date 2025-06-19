package com.google.android.gms.internal.ads;

import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.common.internal.safeparcel.AbstractSafeParcelable;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3489l3;
import java.util.List;

/* loaded from: classes2.dex */
public final class zzbbf extends AbstractSafeParcelable {
    public static final Parcelable.Creator<zzbbf> CREATOR = new C2128h6(1);
    public final String a;
    public final long b;
    public final String c;
    public final String d;
    public final String e;
    public final Bundle f;
    public final boolean g;
    public long h;
    public String i;
    public int j;

    public zzbbf(String str, long j, String str2, String str3, String str4, Bundle bundle, boolean z, long j2, String str5, int i) {
        this.a = str;
        this.b = j;
        this.c = str2 == null ? "" : str2;
        this.d = str3 == null ? "" : str3;
        this.e = str4 == null ? "" : str4;
        this.f = bundle == null ? new Bundle() : bundle;
        this.g = z;
        this.h = j2;
        this.i = str5;
        this.j = i;
    }

    public static zzbbf a(Uri uri) {
        try {
            if (!"gcache".equals(uri.getScheme())) {
                return null;
            }
            List<String> pathSegments = uri.getPathSegments();
            if (pathSegments.size() != 2) {
                com.google.android.gms.ads.internal.util.client.i.h("Expected 2 path parts for namespace and id, found :" + pathSegments.size());
                return null;
            }
            String str = pathSegments.get(0);
            String str2 = pathSegments.get(1);
            String host = uri.getHost();
            String queryParameter = uri.getQueryParameter(DTBMetricsConfiguration.APSMETRICS_URL);
            boolean zEquals = "1".equals(uri.getQueryParameter("read_only"));
            String queryParameter2 = uri.getQueryParameter("expiration");
            long j = queryParameter2 == null ? 0L : Long.parseLong(queryParameter2);
            Bundle bundle = new Bundle();
            for (String str3 : uri.getQueryParameterNames()) {
                if (str3.startsWith("tag.")) {
                    bundle.putString(str3.substring(4), uri.getQueryParameter(str3));
                }
            }
            return new zzbbf(queryParameter, j, host, str, str2, bundle, zEquals, 0L, "", 0);
        } catch (NullPointerException e) {
            e = e;
            com.google.android.gms.ads.internal.util.client.i.i("Unable to parse Uri into cache offering.", e);
            return null;
        } catch (NumberFormatException e2) {
            e = e2;
            com.google.android.gms.ads.internal.util.client.i.i("Unable to parse Uri into cache offering.", e);
            return null;
        }
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int iN = AbstractC3489l3.n(20293, parcel);
        AbstractC3489l3.h(parcel, 2, this.a);
        AbstractC3489l3.m(parcel, 3, 8);
        parcel.writeLong(this.b);
        AbstractC3489l3.h(parcel, 4, this.c);
        AbstractC3489l3.h(parcel, 5, this.d);
        AbstractC3489l3.h(parcel, 6, this.e);
        AbstractC3489l3.c(parcel, 7, this.f);
        AbstractC3489l3.m(parcel, 8, 4);
        parcel.writeInt(this.g ? 1 : 0);
        long j = this.h;
        AbstractC3489l3.m(parcel, 9, 8);
        parcel.writeLong(j);
        AbstractC3489l3.h(parcel, 10, this.i);
        int i2 = this.j;
        AbstractC3489l3.m(parcel, 11, 4);
        parcel.writeInt(i2);
        AbstractC3489l3.o(iN, parcel);
    }
}
