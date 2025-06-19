package com.pubmatic.sdk.common.network;

import android.content.Context;
import android.graphics.Bitmap;
import androidx.annotation.NonNull;
import com.android.volley.ParseError;
import com.android.volley.TimeoutError;
import com.android.volley.VolleyError;
import com.android.volley.r;
import com.android.volley.s;
import com.android.volley.t;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3556x;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.network.a;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class g {

    @NonNull
    private final m a;

    public class a implements s {
        final /* synthetic */ com.pubmatic.sdk.common.network.d a;

        public a(com.pubmatic.sdk.common.network.d dVar) {
            this.a = dVar;
        }

        @Override // com.android.volley.s
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public void onResponse(String str) {
            com.pubmatic.sdk.common.network.d dVar = this.a;
            if (dVar != null) {
                dVar.onSuccess(str);
            }
        }
    }

    public class b extends com.android.volley.toolbox.j {
        final /* synthetic */ com.pubmatic.sdk.common.network.a a;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(int i, String str, s sVar, r rVar, com.pubmatic.sdk.common.network.a aVar) {
            super(i, str, sVar, rVar);
            this.a = aVar;
        }

        @Override // com.android.volley.l
        public byte[] getBody() {
            if (this.a.getPostData() == null) {
                return null;
            }
            return this.a.getPostData().getBytes(StandardCharsets.UTF_8);
        }

        @Override // com.android.volley.l
        public Map<String, String> getHeaders() {
            return this.a.getHeaders();
        }
    }

    public class c implements s {
        final /* synthetic */ com.pubmatic.sdk.common.network.c a;

        public c(com.pubmatic.sdk.common.network.c cVar) {
            this.a = cVar;
        }

        @Override // com.android.volley.s
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public void onResponse(Bitmap bitmap) {
            com.pubmatic.sdk.common.network.c cVar = this.a;
            if (cVar != null) {
                cVar.onSuccess(bitmap);
            }
        }
    }

    public class d implements r {
        final /* synthetic */ com.pubmatic.sdk.common.network.c a;

        public d(com.pubmatic.sdk.common.network.c cVar) {
            this.a = cVar;
        }

        @Override // com.android.volley.r
        public void onErrorResponse(VolleyError volleyError) {
            if (this.a != null) {
                this.a.onFailure(new com.pubmatic.sdk.common.h(1007, "not able to fetch response"));
            }
        }
    }

    public class e implements s {
        final /* synthetic */ com.pubmatic.sdk.common.network.d a;

        public e(com.pubmatic.sdk.common.network.d dVar) {
            this.a = dVar;
        }

        @Override // com.android.volley.s
        /* renamed from: a, reason: merged with bridge method [inline-methods] */
        public void onResponse(JSONObject jSONObject) {
            com.pubmatic.sdk.common.network.d dVar = this.a;
            if (dVar != null) {
                dVar.onSuccess(jSONObject);
            }
        }
    }

    public class f extends com.android.volley.toolbox.g {
        final /* synthetic */ com.pubmatic.sdk.common.network.a a;
        final /* synthetic */ com.pubmatic.sdk.common.network.e b;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public f(int i, String str, JSONObject jSONObject, s sVar, r rVar, com.pubmatic.sdk.common.network.a aVar, com.pubmatic.sdk.common.network.e eVar) {
            super(i, str, jSONObject != null ? jSONObject.toString() : null, sVar, rVar);
            this.a = aVar;
            this.b = eVar;
        }

        @Override // com.android.volley.toolbox.h, com.android.volley.l
        public byte[] getBody() {
            if (this.a.getPostData() == null) {
                return null;
            }
            return this.a.getPostData().getBytes(StandardCharsets.UTF_8);
        }

        @Override // com.android.volley.l
        public Map<String, String> getHeaders() {
            return this.a.getHeaders();
        }

        @Override // com.android.volley.l
        public t parseNetworkResponse(com.android.volley.h hVar) {
            try {
                byte[] bArr = hVar.b;
                Map map = hVar.c;
                JSONObject jSONObject = new JSONObject(new String(bArr, AbstractC3556x.b("utf-8", map)));
                if (this.b != null) {
                    if (map == null) {
                        map = new HashMap();
                    }
                    this.b.onResult(new l(map, hVar.f));
                }
                return new t(jSONObject, AbstractC3556x.a(hVar));
            } catch (UnsupportedEncodingException | JSONException unused) {
                return new t(new ParseError(hVar));
            }
        }
    }

    /* renamed from: com.pubmatic.sdk.common.network.g$g, reason: collision with other inner class name */
    public class C0012g implements com.android.volley.o {
        final /* synthetic */ String a;

        public C0012g(String str) {
            this.a = str;
        }

        @Override // com.android.volley.o
        public boolean apply(com.android.volley.l lVar) {
            if (!this.a.equals(lVar.getTag())) {
                return false;
            }
            POBLog.debug("PMNetworkHandler", android.support.v4.media.session.a.t(new StringBuilder("Cancelled volley Ad Request for Tag <"), this.a, "> "), new Object[0]);
            return true;
        }
    }

    public class h implements r {
        final /* synthetic */ com.pubmatic.sdk.common.network.e a;
        final /* synthetic */ com.pubmatic.sdk.common.network.a b;
        final /* synthetic */ com.pubmatic.sdk.common.network.d c;
        final /* synthetic */ com.pubmatic.sdk.common.network.h d;

        public h(com.pubmatic.sdk.common.network.e eVar, com.pubmatic.sdk.common.network.a aVar, com.pubmatic.sdk.common.network.d dVar, com.pubmatic.sdk.common.network.h hVar) {
            this.a = eVar;
            this.b = aVar;
            this.c = dVar;
        }

        @Override // com.android.volley.r
        public void onErrorResponse(VolleyError volleyError) {
            if (this.a != null) {
                com.android.volley.h hVarA = g.this.a(volleyError, this.b);
                Map map = hVarA.c;
                if (map == null) {
                    map = new HashMap();
                }
                this.a.onResult(new l(map, hVarA.f));
            }
            if (this.c != null) {
                try {
                    com.pubmatic.sdk.common.network.a aVarA = g.this.a(volleyError, this.b, (com.pubmatic.sdk.common.network.h) null);
                    if (aVarA != null) {
                        g.this.sendRequest(aVarA, this.c);
                    } else {
                        this.c.onFailure(g.this.a(volleyError));
                    }
                } catch (VolleyError e) {
                    this.c.onFailure(g.this.a(e));
                }
            }
        }
    }

    public class i implements r {
        final /* synthetic */ com.pubmatic.sdk.common.network.e a;
        final /* synthetic */ com.pubmatic.sdk.common.network.a b;
        final /* synthetic */ com.pubmatic.sdk.common.network.h c;
        final /* synthetic */ com.pubmatic.sdk.common.network.d d;

        public i(com.pubmatic.sdk.common.network.e eVar, com.pubmatic.sdk.common.network.a aVar, com.pubmatic.sdk.common.network.h hVar, com.pubmatic.sdk.common.network.d dVar) {
            this.a = eVar;
            this.b = aVar;
            this.d = dVar;
        }

        @Override // com.android.volley.r
        public void onErrorResponse(VolleyError volleyError) {
            if (this.a != null) {
                com.android.volley.h hVarA = g.this.a(volleyError, this.b);
                Map map = hVarA.c;
                if (map == null) {
                    map = new HashMap();
                }
                this.a.onResult(new l(map, hVarA.f));
            }
            try {
                com.pubmatic.sdk.common.network.a aVarA = g.this.a(volleyError, this.b, (com.pubmatic.sdk.common.network.h) null);
                if (aVarA != null) {
                    g.this.sendJSONRequest(aVarA, this.d);
                    return;
                }
                com.pubmatic.sdk.common.network.d dVar = this.d;
                if (dVar != null) {
                    dVar.onFailure(g.this.a(volleyError));
                }
            } catch (VolleyError e) {
                com.pubmatic.sdk.common.network.d dVar2 = this.d;
                if (dVar2 != null) {
                    dVar2.onFailure(g.this.a(e));
                }
            }
        }
    }

    public g(@NonNull Context context) {
        this(o.newRequestQueue(context, new androidx.work.impl.model.l(new com.quizlet.shared.usecase.srs.a(5))));
    }

    private r b(@NonNull com.pubmatic.sdk.common.network.a aVar, com.pubmatic.sdk.common.network.d dVar, com.pubmatic.sdk.common.network.h hVar, com.pubmatic.sdk.common.network.e eVar) {
        return new i(eVar, aVar, hVar, dVar);
    }

    private void c(@NonNull com.pubmatic.sdk.common.network.a aVar, com.pubmatic.sdk.common.network.d dVar, com.pubmatic.sdk.common.network.h hVar, com.pubmatic.sdk.common.network.e eVar) {
        String url;
        int iA = a(aVar.getRequestMethod());
        if (aVar.getRequestMethod() != a.EnumC0011a.GET || com.pubmatic.sdk.common.utility.o.isNullOrEmpty(aVar.getPostData())) {
            url = aVar.getUrl();
        } else {
            url = aVar.getUrl() + aVar.getPostData();
        }
        f fVar = new f(iA, url, null, new e(dVar), b(aVar, dVar, hVar, eVar), aVar, eVar);
        a(aVar, fVar);
        a(fVar, aVar.getRequestTag());
    }

    public void cancelRequest(@NonNull String str) {
        m mVar = this.a;
        if (mVar != null) {
            mVar.cancelAll((com.android.volley.o) new C0012g(str));
        }
    }

    public void sendImageRequest(com.pubmatic.sdk.common.network.b bVar, com.pubmatic.sdk.common.network.c cVar) {
        if (bVar == null || bVar.getUrl() == null) {
            if (cVar != null) {
                cVar.onFailure(new com.pubmatic.sdk.common.h(1001, "Request parameter or URL is null."));
            }
        } else {
            com.android.volley.toolbox.f fVar = new com.android.volley.toolbox.f(bVar.getUrl(), new c(cVar), bVar.getMaxWidth(), bVar.getMaxHeight(), bVar.getScaleType(), bVar.getDecodeConfig(), new d(cVar));
            a(bVar, fVar);
            a(fVar, bVar.getRequestTag());
        }
    }

    public void sendJSONRequest(com.pubmatic.sdk.common.network.a aVar, com.pubmatic.sdk.common.network.d dVar) {
        c(aVar, dVar, null, null);
    }

    public void sendRequest(@NonNull String str, String str2, com.pubmatic.sdk.common.network.d dVar, com.pubmatic.sdk.common.network.h hVar) {
        com.pubmatic.sdk.common.network.a aVar = new com.pubmatic.sdk.common.network.a();
        aVar.setUrl(str);
        aVar.setRequestTag(str2);
        sendRequest(aVar, dVar, hVar);
    }

    private boolean b(VolleyError volleyError) {
        com.android.volley.h hVar = volleyError.a;
        if (hVar == null) {
            return false;
        }
        int i2 = hVar.a;
        return 301 == i2 || i2 == 302 || i2 == 303;
    }

    public void sendJSONRequest(@NonNull com.pubmatic.sdk.common.network.a aVar, com.pubmatic.sdk.common.network.d dVar, com.pubmatic.sdk.common.network.e eVar) {
        c(aVar, dVar, null, eVar);
    }

    public g(@NonNull m mVar) {
        this.a = mVar;
    }

    private void a(@NonNull com.pubmatic.sdk.common.network.a aVar, @NonNull com.android.volley.l lVar) {
        if (aVar.getTimeout() > 0 || aVar.getRetryCount() > 0) {
            lVar.setRetryPolicy(new com.android.volley.d(aVar.getTimeout(), aVar.getRetryBackoffMultiplier(), aVar.getRetryCount()));
        }
    }

    public void sendRequest(String str, String str2, com.pubmatic.sdk.common.network.d dVar) {
        sendRequest(str, str2, dVar, null);
    }

    public void sendRequest(com.pubmatic.sdk.common.network.a aVar, com.pubmatic.sdk.common.network.d dVar) {
        sendRequest(aVar, dVar, (com.pubmatic.sdk.common.network.h) null);
    }

    public void sendRequest(com.pubmatic.sdk.common.network.a aVar, com.pubmatic.sdk.common.network.d dVar, com.pubmatic.sdk.common.network.h hVar) {
        if (aVar == null || aVar.getUrl() == null || aVar.getRequestMethod() == null) {
            if (dVar != null) {
                dVar.onFailure(new com.pubmatic.sdk.common.h(1001, "Request parameter or URL is null."));
            }
        } else {
            b bVar = new b(a(aVar.getRequestMethod()), aVar.getUrl(), new a(dVar), a(aVar, dVar, hVar, (com.pubmatic.sdk.common.network.e) null), aVar);
            a(aVar, bVar);
            a(bVar, aVar.getRequestTag());
        }
    }

    private <T> void a(@NonNull com.android.volley.l lVar, String str) {
        lVar.setTag(str);
        this.a.add(lVar);
    }

    private int a(a.EnumC0011a enumC0011a) {
        int i2 = com.pubmatic.sdk.common.network.f.a[enumC0011a.ordinal()];
        int i3 = 1;
        if (i2 != 1) {
            i3 = 2;
            if (i2 != 2) {
                i3 = 3;
                if (i2 != 3) {
                    return 0;
                }
            }
        }
        return i3;
    }

    private r a(@NonNull com.pubmatic.sdk.common.network.a aVar, com.pubmatic.sdk.common.network.d dVar, com.pubmatic.sdk.common.network.h hVar, com.pubmatic.sdk.common.network.e eVar) {
        return new h(eVar, aVar, dVar, hVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    @NonNull
    public com.android.volley.h a(@NonNull VolleyError volleyError, @NonNull com.pubmatic.sdk.common.network.a aVar) {
        com.android.volley.h hVar = volleyError.a;
        if (hVar == null) {
            hVar = new com.android.volley.h(0, null, false, volleyError.b, new ArrayList());
        }
        if (hVar.f <= aVar.getTimeout()) {
            return hVar;
        }
        return new com.android.volley.h(hVar.a, hVar.b, hVar.e, aVar.getTimeout(), hVar.d);
    }

    /* JADX INFO: Access modifiers changed from: private */
    @NonNull
    public com.pubmatic.sdk.common.h a(@NonNull VolleyError volleyError) {
        int i2;
        String message = volleyError.getMessage() != null ? volleyError.getMessage() : "Unknown error message.";
        if (volleyError instanceof TimeoutError) {
            return new com.pubmatic.sdk.common.h(1005, message);
        }
        boolean z = volleyError instanceof ParseError;
        com.android.volley.h hVar = volleyError.a;
        if (!z) {
            if (hVar != null && (i2 = hVar.a) >= 500 && i2 < 600) {
                return new com.pubmatic.sdk.common.h(1004, message);
            }
            return new com.pubmatic.sdk.common.h(1006, message);
        }
        if (hVar != null) {
            String str = "Parsing error with HTTP status code: " + hVar.a;
            if (hVar.a == 204) {
                return new com.pubmatic.sdk.common.h(1002, str);
            }
            return new com.pubmatic.sdk.common.h(1007, str);
        }
        return new com.pubmatic.sdk.common.h(1007, message);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public com.pubmatic.sdk.common.network.a a(VolleyError volleyError, com.pubmatic.sdk.common.network.a aVar, com.pubmatic.sdk.common.network.h hVar) throws VolleyError {
        if (!b(volleyError)) {
            return null;
        }
        Map map = volleyError.a.c;
        String str = map != null ? (String) map.get("Location") : null;
        if (str != null) {
            try {
                com.pubmatic.sdk.common.network.a aVarM24clone = aVar.m24clone();
                aVarM24clone.setUrl(str);
                if (hVar != null) {
                    com.pubmatic.sdk.common.network.a aVarA = hVar.a();
                    if (aVarA != null) {
                        return aVarA;
                    }
                }
                return aVarM24clone;
            } catch (CloneNotSupportedException e2) {
                throw new VolleyError(e2);
            }
        }
        throw new VolleyError(0);
    }
}
