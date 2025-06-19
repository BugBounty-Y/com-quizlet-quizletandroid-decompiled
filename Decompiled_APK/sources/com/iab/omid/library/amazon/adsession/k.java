package com.iab.omid.library.amazon.adsession;

import android.app.ActivityManager;
import android.os.Handler;
import android.provider.Settings;
import android.view.View;
import android.webkit.WebView;
import androidx.compose.runtime.internal.m;
import com.google.android.gms.common.api.internal.w;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3763y;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.UUID;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class k extends b {
    public final d a;
    public final c b;
    public final com.iab.omid.library.amazon.internal.f c;
    public m d;
    public com.iab.omid.library.amazon.publisher.a e;
    public boolean f;
    public boolean g;
    public final String h;
    public boolean i;
    public boolean j;

    public k(c cVar, d dVar) throws JSONException {
        com.iab.omid.library.amazon.publisher.a bVar;
        String string = UUID.randomUUID().toString();
        this.c = new com.iab.omid.library.amazon.internal.f();
        this.f = false;
        this.g = false;
        this.b = cVar;
        this.a = dVar;
        this.h = string;
        this.d = new m(null);
        e eVar = e.HTML;
        e eVar2 = dVar.g;
        if (eVar2 == eVar || eVar2 == e.JAVASCRIPT) {
            bVar = new com.iab.omid.library.amazon.publisher.b(string);
            WebView webView = dVar.b;
            if (webView != null && !webView.getSettings().getJavaScriptEnabled()) {
                webView.getSettings().setJavaScriptEnabled(true);
            }
            bVar.b = new m(webView);
        } else {
            bVar = new com.iab.omid.library.amazon.publisher.c(string, Collections.unmodifiableMap(dVar.d));
        }
        this.e = bVar;
        this.e.f();
        com.iab.omid.library.amazon.internal.c.c.a.add(this);
        com.iab.omid.library.amazon.publisher.a aVar = this.e;
        com.iab.omid.library.amazon.internal.h hVar = com.iab.omid.library.amazon.internal.h.a;
        WebView webViewE = aVar.e();
        JSONObject jSONObject = new JSONObject();
        com.iab.omid.library.amazon.utils.b.b(jSONObject, "impressionOwner", cVar.a);
        com.iab.omid.library.amazon.utils.b.b(jSONObject, "mediaEventsOwner", cVar.b);
        com.iab.omid.library.amazon.utils.b.b(jSONObject, "creativeType", cVar.d);
        com.iab.omid.library.amazon.utils.b.b(jSONObject, "impressionType", h.BEGIN_TO_RENDER);
        com.iab.omid.library.amazon.utils.b.b(jSONObject, "isolateVerificationScripts", Boolean.valueOf(cVar.c));
        hVar.a(webViewE, "init", jSONObject, aVar.a);
    }

    @Override // com.iab.omid.library.amazon.adsession.b
    public final void a(View view, g gVar) {
        com.iab.omid.library.amazon.internal.e eVar;
        if (this.g) {
            return;
        }
        com.iab.omid.library.amazon.internal.f fVar = this.c;
        fVar.getClass();
        if (view == null) {
            throw new IllegalArgumentException("FriendlyObstruction is null");
        }
        ArrayList arrayList = fVar.a;
        Iterator it2 = arrayList.iterator();
        while (true) {
            if (!it2.hasNext()) {
                eVar = null;
                break;
            } else {
                eVar = (com.iab.omid.library.amazon.internal.e) it2.next();
                if (eVar.a.get() == view) {
                    break;
                }
            }
        }
        if (eVar == null) {
            arrayList.add(new com.iab.omid.library.amazon.internal.e(view, gVar));
        }
    }

    @Override // com.iab.omid.library.amazon.adsession.b
    public final void b() {
        if (this.g) {
            return;
        }
        this.d.clear();
        if (!this.g) {
            this.c.a.clear();
        }
        this.g = true;
        com.iab.omid.library.amazon.publisher.a aVar = this.e;
        com.iab.omid.library.amazon.internal.h.a.a(aVar.e(), "finishSession", aVar.a);
        com.iab.omid.library.amazon.internal.c cVar = com.iab.omid.library.amazon.internal.c.c;
        boolean z = cVar.b.size() > 0;
        cVar.a.remove(this);
        ArrayList arrayList = cVar.b;
        arrayList.remove(this);
        if (z && arrayList.size() <= 0) {
            com.airbnb.lottie.animation.keyframe.c cVarD = com.airbnb.lottie.animation.keyframe.c.d();
            cVarD.getClass();
            com.iab.omid.library.amazon.walking.a aVar2 = com.iab.omid.library.amazon.walking.a.g;
            aVar2.getClass();
            Handler handler = com.iab.omid.library.amazon.walking.a.i;
            if (handler != null) {
                handler.removeCallbacks(com.iab.omid.library.amazon.walking.a.k);
                com.iab.omid.library.amazon.walking.a.i = null;
            }
            aVar2.a.clear();
            com.iab.omid.library.amazon.walking.a.h.post(new w(aVar2, 17));
            com.iab.omid.library.amazon.internal.b bVar = com.iab.omid.library.amazon.internal.b.e;
            bVar.b = false;
            bVar.d = null;
            com.iab.omid.library.amazon.devicevolume.a aVar3 = (com.iab.omid.library.amazon.devicevolume.a) cVarD.c;
            aVar3.a.getContentResolver().unregisterContentObserver(aVar3);
        }
        this.e.d();
        this.e = null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.iab.omid.library.amazon.adsession.b
    public final void c(WebView webView) {
        if (this.g) {
            return;
        }
        AbstractC3763y.a(webView, "AdView is null");
        if (((View) this.d.get()) == webView) {
            return;
        }
        this.d = new m(webView);
        com.iab.omid.library.amazon.publisher.a aVar = this.e;
        aVar.getClass();
        aVar.e = System.nanoTime();
        aVar.d = 1;
        Collection<k> collectionUnmodifiableCollection = Collections.unmodifiableCollection(com.iab.omid.library.amazon.internal.c.c.a);
        if (collectionUnmodifiableCollection == null || collectionUnmodifiableCollection.isEmpty()) {
            return;
        }
        for (k kVar : collectionUnmodifiableCollection) {
            if (kVar != this && ((View) kVar.d.get()) == webView) {
                kVar.d.clear();
            }
        }
    }

    @Override // com.iab.omid.library.amazon.adsession.b
    public final void d() {
        if (this.f) {
            return;
        }
        this.f = true;
        com.iab.omid.library.amazon.internal.c cVar = com.iab.omid.library.amazon.internal.c.c;
        boolean z = cVar.b.size() > 0;
        cVar.b.add(this);
        if (!z) {
            com.airbnb.lottie.animation.keyframe.c cVarD = com.airbnb.lottie.animation.keyframe.c.d();
            cVarD.getClass();
            com.iab.omid.library.amazon.internal.b bVar = com.iab.omid.library.amazon.internal.b.e;
            bVar.d = cVarD;
            bVar.b = true;
            ActivityManager.RunningAppProcessInfo runningAppProcessInfo = new ActivityManager.RunningAppProcessInfo();
            ActivityManager.getMyMemoryState(runningAppProcessInfo);
            boolean z2 = runningAppProcessInfo.importance == 100 || bVar.d();
            bVar.c = z2;
            bVar.b(z2);
            com.iab.omid.library.amazon.walking.a.g.getClass();
            com.iab.omid.library.amazon.walking.a.b();
            com.iab.omid.library.amazon.devicevolume.a aVar = (com.iab.omid.library.amazon.devicevolume.a) cVarD.c;
            aVar.e = aVar.a();
            aVar.b();
            aVar.a.getContentResolver().registerContentObserver(Settings.System.CONTENT_URI, true, aVar);
        }
        float f = com.airbnb.lottie.animation.keyframe.c.d().a;
        com.iab.omid.library.amazon.publisher.a aVar2 = this.e;
        com.iab.omid.library.amazon.internal.h.a.a(aVar2.e(), "setDeviceVolume", Float.valueOf(f), aVar2.a);
        com.iab.omid.library.amazon.publisher.a aVar3 = this.e;
        Date date = com.iab.omid.library.amazon.internal.a.f.b;
        aVar3.c(date != null ? (Date) date.clone() : null);
        this.e.a(this, this.a);
    }
}
