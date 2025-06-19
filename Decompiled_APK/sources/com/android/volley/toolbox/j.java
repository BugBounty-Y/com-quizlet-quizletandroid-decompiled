package com.android.volley.toolbox;

import com.android.volley.l;
import com.android.volley.r;
import com.android.volley.s;
import com.android.volley.t;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3556x;
import java.io.UnsupportedEncodingException;

/* loaded from: classes.dex */
public abstract class j extends l {
    private s mListener;
    private final Object mLock;

    public j(int i, String str, s sVar, r rVar) {
        super(i, str, rVar);
        this.mLock = new Object();
        this.mListener = sVar;
    }

    @Override // com.android.volley.l
    public void cancel() {
        super.cancel();
        synchronized (this.mLock) {
            this.mListener = null;
        }
    }

    @Override // com.android.volley.l
    public t parseNetworkResponse(com.android.volley.h hVar) {
        String str;
        try {
            str = new String(hVar.b, AbstractC3556x.b("ISO-8859-1", hVar.c));
        } catch (UnsupportedEncodingException unused) {
            str = new String(hVar.b);
        }
        return new t(str, AbstractC3556x.a(hVar));
    }

    @Override // com.android.volley.l
    public void deliverResponse(String str) {
        s sVar;
        synchronized (this.mLock) {
            sVar = this.mListener;
        }
        if (sVar != null) {
            sVar.onResponse(str);
        }
    }
}
