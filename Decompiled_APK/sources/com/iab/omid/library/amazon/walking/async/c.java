package com.iab.omid.library.amazon.walking.async;

import android.text.TextUtils;
import com.iab.omid.library.amazon.adsession.k;
import com.iab.omid.library.amazon.internal.h;
import java.util.Collections;
import java.util.HashSet;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c extends a {
    public final HashSet c;
    public final JSONObject d;
    public final long e;
    public final /* synthetic */ int f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(com.quizlet.data.repository.qclass.c cVar, HashSet hashSet, JSONObject jSONObject, long j, int i) {
        super(cVar);
        this.f = i;
        this.c = new HashSet(hashSet);
        this.d = jSONObject;
        this.e = j;
    }

    @Override // com.iab.omid.library.amazon.walking.async.a
    /* renamed from: a */
    public final void onPostExecute(String str) {
        com.iab.omid.library.amazon.internal.c cVar;
        switch (this.f) {
            case 0:
                com.iab.omid.library.amazon.internal.c cVar2 = com.iab.omid.library.amazon.internal.c.c;
                if (cVar2 != null) {
                    for (k kVar : Collections.unmodifiableCollection(cVar2.a)) {
                        if (this.c.contains(kVar.h)) {
                            com.iab.omid.library.amazon.publisher.a aVar = kVar.e;
                            if (this.e >= aVar.e && aVar.d != 3) {
                                aVar.d = 3;
                                h.a.a(aVar.e(), "setNativeViewHierarchy", str, aVar.a);
                            }
                        }
                    }
                }
                super.onPostExecute(str);
                break;
            default:
                if (!TextUtils.isEmpty(str) && (cVar = com.iab.omid.library.amazon.internal.c.c) != null) {
                    for (k kVar2 : Collections.unmodifiableCollection(cVar.a)) {
                        if (this.c.contains(kVar2.h)) {
                            com.iab.omid.library.amazon.publisher.a aVar2 = kVar2.e;
                            if (this.e >= aVar2.e) {
                                aVar2.d = 2;
                                h.a.a(aVar2.e(), "setNativeViewHierarchy", str, aVar2.a);
                            }
                        }
                    }
                }
                super.onPostExecute(str);
                break;
        }
    }

    @Override // android.os.AsyncTask
    public final Object doInBackground(Object[] objArr) {
        switch (this.f) {
            case 0:
                return this.d.toString();
            default:
                com.quizlet.data.repository.qclass.c cVar = this.b;
                JSONObject jSONObject = (JSONObject) cVar.b;
                JSONObject jSONObject2 = this.d;
                if (com.iab.omid.library.amazon.utils.b.e(jSONObject2, jSONObject)) {
                    return null;
                }
                cVar.b = jSONObject2;
                return jSONObject2.toString();
        }
    }

    @Override // com.iab.omid.library.amazon.walking.async.a, android.os.AsyncTask
    public final /* bridge */ /* synthetic */ void onPostExecute(Object obj) {
        switch (this.f) {
            case 0:
                onPostExecute((String) obj);
                break;
            default:
                onPostExecute((String) obj);
                break;
        }
    }
}
