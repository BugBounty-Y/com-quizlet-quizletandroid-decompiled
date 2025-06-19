package com.google.android.gms.ads.nonagon.signalgeneration;

import androidx.appcompat.app.L;
import com.google.android.gms.internal.ads.AbstractC1911c8;
import com.google.android.gms.internal.ads.I3;
import com.google.android.gms.internal.ads.I7;
import java.util.Locale;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class s extends com.google.android.gms.ads.query.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ Object c;

    public /* synthetic */ s(String str, int i, Object obj) {
        this.a = i;
        this.b = str;
        this.c = obj;
    }

    @Override // com.google.android.gms.ads.query.a
    public final void a(String str) {
        switch (this.a) {
            case 0:
                com.google.android.gms.ads.internal.util.client.i.h("Failed to generate query info for the tagging library, error: ".concat(String.valueOf(str)));
                boolean zBooleanValue = ((Boolean) AbstractC1911c8.c.o()).booleanValue();
                C1635a c1635a = (C1635a) this.c;
                String strConcat = zBooleanValue ? ",\"as\":".concat(c1635a.k.a().toString()) : "";
                Locale locale = Locale.getDefault();
                I3 i3 = AbstractC1911c8.e;
                String str2 = String.format(locale, "window.postMessage({\"paw_id\":\"%1$s\",\"error\":\"%2$s\",\"sdk_ttl_ms\":%3$d%4$s}, '*');", this.b, str, Long.valueOf(((Boolean) i3.o()).booleanValue() ? ((Long) AbstractC1911c8.h.o()).longValue() : 0L), strConcat);
                if (((Boolean) i3.o()).booleanValue()) {
                    try {
                        c1635a.h.execute(new com.google.common.util.concurrent.d(19, this, str2));
                    } catch (RuntimeException e) {
                        com.google.android.gms.ads.internal.j.C.h.g("TaggingLibraryJsInterface.getQueryInfo.onFailure", e);
                    }
                } else {
                    c1635a.b.evaluateJavascript(str2, null);
                }
                if (((Boolean) AbstractC1911c8.c.o()).booleanValue() && ((Boolean) AbstractC1911c8.d.o()).booleanValue()) {
                    y yVar = c1635a.l;
                    yVar.getClass();
                    yVar.c.execute(new x(yVar, 0));
                    break;
                }
                break;
            default:
                com.google.android.gms.ads.internal.util.client.i.h("Failed to generate query info for Custom Tab error: ".concat(String.valueOf(str)));
                try {
                    I7 i7 = (I7) this.c;
                    i7.g.h(i7.a(this.b, str).toString());
                    break;
                } catch (JSONException e2) {
                    com.google.android.gms.ads.internal.util.client.i.f("Error creating PACT Error Response JSON: ", e2);
                }
        }
    }

    @Override // com.google.android.gms.ads.query.a
    public final void b(L l) throws JSONException {
        String str;
        switch (this.a) {
            case 0:
                String str2 = this.b;
                C1635a c1635a = (C1635a) this.c;
                v vVar = c1635a.k;
                String str3 = ((androidx.emoji2.text.r) l.b).a;
                try {
                    JSONObject jSONObject = new JSONObject();
                    jSONObject.put("paw_id", str2);
                    if (((Boolean) AbstractC1911c8.c.o()).booleanValue()) {
                        jSONObject.put("as", vVar.a());
                    }
                    jSONObject.put("sdk_ttl_ms", ((Boolean) AbstractC1911c8.e.o()).booleanValue() ? ((Long) AbstractC1911c8.h.o()).longValue() : 0L);
                    jSONObject.put("signal", str3);
                    str = String.format(Locale.getDefault(), "window.postMessage(%1$s, '*');", jSONObject);
                } catch (JSONException unused) {
                    String strConcat = ((Boolean) AbstractC1911c8.c.o()).booleanValue() ? ",\"as\":".concat(vVar.a().toString()) : "";
                    str = String.format(Locale.getDefault(), "window.postMessage({\"paw_id\":\"%1$s\",\"signal\":\"%2$s\",\"sdk_ttl_ms\":%3$d%4$s}, '*');", str2, ((androidx.emoji2.text.r) l.b).a, Long.valueOf(((Boolean) AbstractC1911c8.e.o()).booleanValue() ? ((Long) AbstractC1911c8.h.o()).longValue() : 0L), strConcat);
                }
                if (((Boolean) AbstractC1911c8.e.o()).booleanValue()) {
                    try {
                        c1635a.h.execute(new androidx.camera.core.impl.utils.futures.h(20, this, str));
                    } catch (RuntimeException e) {
                        com.google.android.gms.ads.internal.j.C.h.g("TaggingLibraryJsInterface.getQueryInfo.onSuccess", e);
                    }
                } else {
                    c1635a.b.evaluateJavascript(str, null);
                }
                if (((Boolean) AbstractC1911c8.c.o()).booleanValue() && ((Boolean) AbstractC1911c8.d.o()).booleanValue()) {
                    y yVar = c1635a.l;
                    yVar.getClass();
                    yVar.c.execute(new x(yVar, 0));
                    break;
                }
                break;
            default:
                String str4 = ((androidx.emoji2.text.r) l.b).a;
                try {
                    I7 i7 = (I7) this.c;
                    i7.g.h(i7.b(this.b, str4).toString());
                    break;
                } catch (JSONException e2) {
                    com.google.android.gms.ads.internal.util.client.i.f("Error creating PACT Signal Response JSON: ", e2);
                }
        }
    }
}
