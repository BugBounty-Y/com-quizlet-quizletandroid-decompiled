package com.android.volley.toolbox;

import com.android.volley.l;
import com.android.volley.r;
import com.android.volley.s;

/* loaded from: classes.dex */
public abstract class h extends l {
    protected static final String PROTOCOL_CHARSET = "utf-8";
    private static final String PROTOCOL_CONTENT_TYPE = "application/json; charset=utf-8";
    private s mListener;
    private final Object mLock;
    private final String mRequestBody;

    public h(int i, String str, String str2, s sVar, r rVar) {
        super(i, str, rVar);
        this.mLock = new Object();
        this.mListener = sVar;
        this.mRequestBody = str2;
    }

    @Override // com.android.volley.l
    public void cancel() {
        super.cancel();
        synchronized (this.mLock) {
            this.mListener = null;
        }
    }

    @Override // com.android.volley.l
    public void deliverResponse(Object obj) {
        s sVar;
        synchronized (this.mLock) {
            sVar = this.mListener;
        }
        if (sVar != null) {
            sVar.onResponse(obj);
        }
    }

    @Override // com.android.volley.l
    public abstract byte[] getBody();

    @Override // com.android.volley.l
    public String getBodyContentType() {
        return PROTOCOL_CONTENT_TYPE;
    }

    @Override // com.android.volley.l
    @Deprecated
    public byte[] getPostBody() {
        return getBody();
    }

    @Override // com.android.volley.l
    @Deprecated
    public String getPostBodyContentType() {
        return getBodyContentType();
    }
}
