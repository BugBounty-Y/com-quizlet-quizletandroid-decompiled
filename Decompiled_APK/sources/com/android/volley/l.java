package com.android.volley;

import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes.dex */
public abstract class l implements Comparable {
    private static final String DEFAULT_PARAMS_ENCODING = "UTF-8";
    private a mCacheEntry;
    private boolean mCanceled;
    private final int mDefaultTrafficStatsTag;
    private r mErrorListener;
    private final x mEventLog;
    private final Object mLock;
    private final int mMethod;
    private j mRequestCompleteListener;
    private q mRequestQueue;
    private boolean mResponseDelivered;
    private v mRetryPolicy;
    private Integer mSequence;
    private boolean mShouldCache;
    private boolean mShouldRetryConnectionErrors;
    private boolean mShouldRetryServerErrors;
    private Object mTag;
    private final String mUrl;

    public l(int i, String str, r rVar) {
        Uri uri;
        String host;
        this.mEventLog = x.c ? new x() : null;
        this.mLock = new Object();
        this.mShouldCache = true;
        int iHashCode = 0;
        this.mCanceled = false;
        this.mResponseDelivered = false;
        this.mShouldRetryServerErrors = false;
        this.mShouldRetryConnectionErrors = false;
        this.mCacheEntry = null;
        this.mMethod = i;
        this.mUrl = str;
        this.mErrorListener = rVar;
        setRetryPolicy(new d(2500, 1.0f, 1));
        if (!TextUtils.isEmpty(str) && (uri = Uri.parse(str)) != null && (host = uri.getHost()) != null) {
            iHashCode = host.hashCode();
        }
        this.mDefaultTrafficStatsTag = iHashCode;
    }

    public static byte[] a(String str, Map map) {
        StringBuilder sb = new StringBuilder();
        try {
            for (Map.Entry entry : map.entrySet()) {
                if (entry.getKey() == null || entry.getValue() == null) {
                    throw new IllegalArgumentException(String.format("Request#getParams() or Request#getPostParams() returned a map containing a null key or value: (%s, %s). All keys and values must be non-null.", entry.getKey(), entry.getValue()));
                }
                sb.append(URLEncoder.encode((String) entry.getKey(), str));
                sb.append('=');
                sb.append(URLEncoder.encode((String) entry.getValue(), str));
                sb.append('&');
            }
            return sb.toString().getBytes(str);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(AbstractC0147y.d("Encoding not supported: ", str), e);
        }
    }

    public void addMarker(String str) {
        if (x.c) {
            this.mEventLog.a(Thread.currentThread().getId(), str);
        }
    }

    public void cancel() {
        synchronized (this.mLock) {
            this.mCanceled = true;
            this.mErrorListener = null;
        }
    }

    public void deliverError(VolleyError volleyError) {
        r rVar;
        synchronized (this.mLock) {
            rVar = this.mErrorListener;
        }
        if (rVar != null) {
            rVar.onErrorResponse(volleyError);
        }
    }

    public abstract void deliverResponse(Object obj);

    public void finish(String str) {
        q qVar = this.mRequestQueue;
        if (qVar != null) {
            qVar.finish(this);
        }
        if (x.c) {
            long id = Thread.currentThread().getId();
            if (Looper.myLooper() != Looper.getMainLooper()) {
                new Handler(Looper.getMainLooper()).post(new i(this, str, id, 0));
            } else {
                this.mEventLog.a(id, str);
                this.mEventLog.b(toString());
            }
        }
    }

    public byte[] getBody() throws AuthFailureError {
        Map<String, String> params = getParams();
        if (params == null || params.size() <= 0) {
            return null;
        }
        return a(getParamsEncoding(), params);
    }

    public String getBodyContentType() {
        return "application/x-www-form-urlencoded; charset=" + getParamsEncoding();
    }

    public a getCacheEntry() {
        return this.mCacheEntry;
    }

    public String getCacheKey() {
        String url = getUrl();
        int method = getMethod();
        if (method == 0 || method == -1) {
            return url;
        }
        return Integer.toString(method) + '-' + url;
    }

    public r getErrorListener() {
        r rVar;
        synchronized (this.mLock) {
            rVar = this.mErrorListener;
        }
        return rVar;
    }

    public Map getHeaders() {
        return Collections.EMPTY_MAP;
    }

    public int getMethod() {
        return this.mMethod;
    }

    public Map<String, String> getParams() throws AuthFailureError {
        return null;
    }

    public String getParamsEncoding() {
        return DEFAULT_PARAMS_ENCODING;
    }

    @Deprecated
    public byte[] getPostBody() throws AuthFailureError {
        Map<String, String> postParams = getPostParams();
        if (postParams == null || postParams.size() <= 0) {
            return null;
        }
        return a(getPostParamsEncoding(), postParams);
    }

    @Deprecated
    public String getPostBodyContentType() {
        return getBodyContentType();
    }

    @Deprecated
    public Map<String, String> getPostParams() throws AuthFailureError {
        return getParams();
    }

    @Deprecated
    public String getPostParamsEncoding() {
        return getParamsEncoding();
    }

    public k getPriority() {
        return k.b;
    }

    public v getRetryPolicy() {
        return this.mRetryPolicy;
    }

    public final int getSequence() {
        Integer num = this.mSequence;
        if (num != null) {
            return num.intValue();
        }
        throw new IllegalStateException("getSequence called before setSequence");
    }

    public Object getTag() {
        return this.mTag;
    }

    public final int getTimeoutMs() {
        return ((d) getRetryPolicy()).a;
    }

    public int getTrafficStatsTag() {
        return this.mDefaultTrafficStatsTag;
    }

    public String getUrl() {
        return this.mUrl;
    }

    public boolean hasHadResponseDelivered() {
        boolean z;
        synchronized (this.mLock) {
            z = this.mResponseDelivered;
        }
        return z;
    }

    public boolean isCanceled() {
        boolean z;
        synchronized (this.mLock) {
            z = this.mCanceled;
        }
        return z;
    }

    public void markDelivered() {
        synchronized (this.mLock) {
            this.mResponseDelivered = true;
        }
    }

    public void notifyListenerResponseNotUsable() {
        j jVar;
        synchronized (this.mLock) {
            jVar = this.mRequestCompleteListener;
        }
        if (jVar != null) {
            ((com.google.firebase.messaging.u) jVar).i(this);
        }
    }

    public void notifyListenerResponseReceived(t tVar) {
        j jVar;
        List list;
        synchronized (this.mLock) {
            jVar = this.mRequestCompleteListener;
        }
        if (jVar != null) {
            com.google.firebase.messaging.u uVar = (com.google.firebase.messaging.u) jVar;
            a aVar = tVar.b;
            if (aVar != null) {
                if (aVar.e >= System.currentTimeMillis()) {
                    String cacheKey = getCacheKey();
                    synchronized (uVar) {
                        list = (List) ((HashMap) uVar.a).remove(cacheKey);
                    }
                    if (list != null) {
                        if (y.a) {
                            y.c("Releasing %d waiting requests for cacheKey=%s.", Integer.valueOf(list.size()), cacheKey);
                        }
                        Iterator it2 = list.iterator();
                        while (it2.hasNext()) {
                            ((com.airbnb.lottie.network.d) ((u) uVar.b)).p((l) it2.next(), tVar, null);
                        }
                        return;
                    }
                    return;
                }
            }
            uVar.i(this);
        }
    }

    public VolleyError parseNetworkError(VolleyError volleyError) {
        return volleyError;
    }

    public abstract t parseNetworkResponse(h hVar);

    public void sendEvent(int i) {
        q qVar = this.mRequestQueue;
        if (qVar != null) {
            qVar.sendRequestEvent(this, i);
        }
    }

    public l setCacheEntry(a aVar) {
        this.mCacheEntry = aVar;
        return this;
    }

    public void setNetworkRequestCompleteListener(j jVar) {
        synchronized (this.mLock) {
            this.mRequestCompleteListener = jVar;
        }
    }

    public l setRequestQueue(q qVar) {
        this.mRequestQueue = qVar;
        return this;
    }

    public l setRetryPolicy(v vVar) {
        this.mRetryPolicy = vVar;
        return this;
    }

    public final l setSequence(int i) {
        this.mSequence = Integer.valueOf(i);
        return this;
    }

    public final l setShouldCache(boolean z) {
        this.mShouldCache = z;
        return this;
    }

    public final l setShouldRetryConnectionErrors(boolean z) {
        this.mShouldRetryConnectionErrors = z;
        return this;
    }

    public final l setShouldRetryServerErrors(boolean z) {
        this.mShouldRetryServerErrors = z;
        return this;
    }

    public l setTag(Object obj) {
        this.mTag = obj;
        return this;
    }

    public final boolean shouldCache() {
        return this.mShouldCache;
    }

    public final boolean shouldRetryConnectionErrors() {
        return this.mShouldRetryConnectionErrors;
    }

    public final boolean shouldRetryServerErrors() {
        return this.mShouldRetryServerErrors;
    }

    public String toString() {
        String str = "0x" + Integer.toHexString(getTrafficStatsTag());
        StringBuilder sb = new StringBuilder();
        sb.append(isCanceled() ? "[X] " : "[ ] ");
        sb.append(getUrl());
        sb.append(" ");
        sb.append(str);
        sb.append(" ");
        sb.append(getPriority());
        sb.append(" ");
        sb.append(this.mSequence);
        return sb.toString();
    }

    @Override // java.lang.Comparable
    public int compareTo(l lVar) {
        k priority = getPriority();
        k priority2 = lVar.getPriority();
        return priority == priority2 ? this.mSequence.intValue() - lVar.mSequence.intValue() : priority2.ordinal() - priority.ordinal();
    }
}
