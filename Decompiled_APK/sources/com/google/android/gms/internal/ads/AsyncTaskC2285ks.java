package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import java.util.Collections;
import java.util.HashSet;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.ks, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class AsyncTaskC2285ks extends AbstractAsyncTaskC2200is {
    public final HashSet c;
    public final JSONObject d;
    public final long e;
    public final /* synthetic */ int f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AsyncTaskC2285ks(Fi fi, HashSet hashSet, JSONObject jSONObject, long j, int i) {
        super(fi);
        this.f = i;
        this.c = new HashSet(hashSet);
        this.d = jSONObject;
        this.e = j;
    }

    @Override // com.google.android.gms.internal.ads.AbstractAsyncTaskC2200is
    /* renamed from: a */
    public final void onPostExecute(String str) {
        Qr qr;
        switch (this.f) {
            case 0:
                b(str);
                super.onPostExecute(str);
                break;
            default:
                if (!TextUtils.isEmpty(str) && (qr = Qr.c) != null) {
                    for (Hr hr : Collections.unmodifiableCollection(qr.a)) {
                        if (this.c.contains(hr.g)) {
                            Zr zr = hr.d;
                            if (this.e >= zr.c) {
                                zr.d = 2;
                                AbstractC1795We.o(zr.a(), "setNativeViewHierarchy", str, zr.a);
                            }
                        }
                    }
                }
                super.onPostExecute(str);
                break;
        }
    }

    public void b(String str) {
        Qr qr = Qr.c;
        if (qr != null) {
            for (Hr hr : Collections.unmodifiableCollection(qr.a)) {
                if (this.c.contains(hr.g)) {
                    Zr zr = hr.d;
                    if (this.e >= zr.c && zr.d != 3) {
                        zr.d = 3;
                        AbstractC1795We.o(zr.a(), "setNativeViewHierarchy", str, zr.a);
                    }
                }
            }
        }
    }

    @Override // android.os.AsyncTask
    public final Object doInBackground(Object[] objArr) {
        switch (this.f) {
            case 0:
                return this.d.toString();
            default:
                Fi fi = this.b;
                JSONObject jSONObject = (JSONObject) fi.b;
                JSONObject jSONObject2 = this.d;
                if (AbstractC1938cs.e(jSONObject2, jSONObject)) {
                    return null;
                }
                fi.b = jSONObject2;
                return jSONObject2.toString();
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractAsyncTaskC2200is, android.os.AsyncTask
    public final /* synthetic */ void onPostExecute(Object obj) {
        switch (this.f) {
            case 0:
                String str = (String) obj;
                b(str);
                super.onPostExecute(str);
                break;
            default:
                onPostExecute((String) obj);
                break;
        }
    }
}
