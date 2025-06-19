package com.google.android.gms.internal.ads;

import android.app.UiModeManager;
import android.os.Handler;
import android.view.View;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final /* synthetic */ class Sq implements Gq, At, InterfaceC2390nA, Bt {
    public Object a;

    public /* synthetic */ Sq(Object obj) {
        this.a = obj;
    }

    public JSONObject a(View view) throws JSONException {
        int currentModeType;
        JSONObject jSONObjectA = AbstractC1938cs.a(0, 0, 0, 0);
        UiModeManager uiModeManager = AbstractC1972di.N;
        int i = (uiModeManager == null || (currentModeType = uiModeManager.getCurrentModeType()) == 1 || currentModeType != 4) ? 2 : AbstractC1981ds.a;
        int i2 = i - 1;
        if (i == 0) {
            throw null;
        }
        try {
            jSONObjectA.put("noOutputDevice", i2 == 0);
            return jSONObjectA;
        } catch (JSONException e) {
            LA.l("Error with setting output device status", e);
            return jSONObjectA;
        }
    }

    @Override // com.google.android.gms.internal.ads.Gq
    public Object b(Object obj) {
        if (((Boolean) R7.c.o()).booleanValue()) {
            ((Pq) this.a).zzi();
        }
        return obj;
    }

    public void c(Exception exc) {
        AbstractC2096gb.A("MediaCodecAudioRenderer", "Audio sink error", exc);
        Fp fp = ((C2651tE) this.a).F1;
        Handler handler = (Handler) fp.b;
        if (handler != null) {
            handler.post(new RunnableC2180iE(fp, exc, 6));
        }
    }

    public void d(BA ba) {
        if (!ba.k()) {
            if (!(ba instanceof C2520qB)) {
                throw new IllegalArgumentException("Has a new type of ByteString been created? Found ".concat(String.valueOf(ba.getClass())));
            }
            C2520qB c2520qB = (C2520qB) ba;
            d(c2520qB.d);
            d(c2520qB.e);
            return;
        }
        int iBinarySearch = Arrays.binarySearch(C2520qB.h, ba.g());
        if (iBinarySearch < 0) {
            iBinarySearch = (-(iBinarySearch + 1)) - 1;
        }
        ArrayDeque arrayDeque = (ArrayDeque) this.a;
        int iZ = C2520qB.z(iBinarySearch + 1);
        if (arrayDeque.isEmpty() || ((BA) arrayDeque.peek()).g() >= iZ) {
            arrayDeque.push(ba);
            return;
        }
        int iZ2 = C2520qB.z(iBinarySearch);
        BA c2520qB2 = (BA) arrayDeque.pop();
        while (!arrayDeque.isEmpty() && ((BA) arrayDeque.peek()).g() < iZ2) {
            c2520qB2 = new C2520qB((BA) arrayDeque.pop(), c2520qB2);
        }
        C2520qB c2520qB3 = new C2520qB(c2520qB2, ba);
        while (!arrayDeque.isEmpty()) {
            int iBinarySearch2 = Arrays.binarySearch(C2520qB.h, c2520qB3.c);
            if (iBinarySearch2 < 0) {
                iBinarySearch2 = (-(iBinarySearch2 + 1)) - 1;
            }
            if (((BA) arrayDeque.peek()).g() >= C2520qB.z(iBinarySearch2 + 1)) {
                break;
            } else {
                c2520qB3 = new C2520qB((BA) arrayDeque.pop(), c2520qB3);
            }
        }
        arrayDeque.push(c2520qB3);
    }

    @Override // com.google.android.gms.internal.ads.At
    public Iterator e(C2883yp c2883yp, CharSequence charSequence) {
        return new C2844xt(charSequence, new C2586rt(((C2629st) this.a).b.matcher(charSequence)), 1);
    }

    @Override // com.google.android.gms.internal.ads.Bt
    public Object zza() {
        return (VF) this.a;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2390nA
    public Object zza(String str) throws GeneralSecurityException {
        String[] strArr = {"GmsCore_OpenSSL", "AndroidOpenSSL", "Conscrypt"};
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < 3; i++) {
            Provider provider = Security.getProvider(strArr[i]);
            if (provider != null) {
                arrayList.add(provider);
            }
        }
        Iterator it2 = arrayList.iterator();
        Exception exc = null;
        while (it2.hasNext()) {
            try {
                return ((C2806wy) this.a).i(str, (Provider) it2.next());
            } catch (Exception e) {
                if (exc == null) {
                    exc = e;
                }
            }
        }
        throw new GeneralSecurityException("No good Provider found.", exc);
    }
}
