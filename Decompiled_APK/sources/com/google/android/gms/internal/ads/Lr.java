package com.google.android.gms.internal.ads;

import android.net.Uri;
import android.webkit.WebView;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Lr implements androidx.webkit.h, OnCompleteListener, At, InterfaceC2390nA, InterfaceC2001eB, Bt, Pk {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ Lr(RD rd, QC qc) {
        this.a = 9;
        this.b = qc;
    }

    @Override // com.google.android.gms.internal.ads.Pk
    /* renamed from: b */
    public void mo10b(Object obj) {
        switch (this.a) {
            case 8:
                WD wd = (WD) obj;
                RD rdL = wd.l();
                wd.i(rdL, 25, new C2883yp(rdL, (C1740Nd) this.b));
                break;
            case 9:
                ((SD) obj).k((QC) this.b);
                break;
            default:
                ((SD) obj).e();
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2001eB
    public C2391nB c(Class cls) {
        for (int i = 0; i < 2; i++) {
            InterfaceC2001eB interfaceC2001eB = ((InterfaceC2001eB[]) this.b)[i];
            if (interfaceC2001eB.d(cls)) {
                return interfaceC2001eB.c(cls);
            }
        }
        throw new UnsupportedOperationException("No factory is available for message type: ".concat(cls.getName()));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2001eB
    public boolean d(Class cls) {
        for (int i = 0; i < 2; i++) {
            if (((InterfaceC2001eB[]) this.b)[i].d(cls)) {
                return true;
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.At
    public Iterator e(C2883yp c2883yp, CharSequence charSequence) {
        return new C2844xt(charSequence, (C2501pt) this.b, 0);
    }

    @Override // com.google.android.gms.tasks.OnCompleteListener
    public void onComplete(Task task) {
        boolean zJ = task.j();
        Us us = (Us) this.b;
        if (zJ) {
            us.cancel(false);
            return;
        }
        if (task.l()) {
            us.g(task.h());
            return;
        }
        Exception excG = task.g();
        if (excG == null) {
            throw new IllegalStateException();
        }
        us.h(excG);
    }

    @Override // androidx.webkit.h
    public void onPostMessage(WebView webView, androidx.webkit.d dVar, Uri uri, boolean z, androidx.webkit.a aVar) throws JSONException {
        try {
            JSONObject jSONObject = new JSONObject(dVar.a());
            String string = jSONObject.getString("method");
            String string2 = jSONObject.getJSONObject("data").getString("adSessionId");
            boolean zEquals = string.equals("startSession");
            com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = (com.quizlet.data.repository.studysetwithcreatorinclass.g) this.b;
            if (zEquals) {
                com.quizlet.data.repository.studysetwithcreatorinclass.g.A(gVar, string2);
                return;
            }
            if (string.equals("finishSession")) {
                HashMap map = (HashMap) gVar.e;
                Hr hr = (Hr) map.get(string2);
                if (hr != null) {
                    hr.a();
                    map.remove(string2);
                }
            }
        } catch (JSONException e) {
            LA.l("Error parsing JS message in JavaScriptSessionService.", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.Bt
    public Object zza() {
        return (Ts) this.b;
    }

    public /* synthetic */ Lr(RD rd, Object obj, long j) {
        this.a = 10;
        this.b = obj;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2390nA
    public Object zza(String str) {
        return ((C2806wy) this.b).i(str, null);
    }

    public /* synthetic */ Lr(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public Lr() {
        this.a = 13;
        this.b = new CopyOnWriteArrayList();
    }
}
