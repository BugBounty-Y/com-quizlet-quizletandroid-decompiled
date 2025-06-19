package com.facebook.internal;

import android.app.ProgressDialog;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.widget.ImageView;
import com.facebook.AccessToken;
import com.facebook.FacebookException;
import com.facebook.FacebookGraphResponseException;
import com.facebook.FacebookRequestError;
import com.google.android.gms.internal.mlkit_vision_common.L2;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class O extends AsyncTask {
    public final String a;
    public final Bundle b;
    public Exception[] c;
    public final /* synthetic */ S d;

    public O(S s, String action, Bundle parameters) {
        Intrinsics.checkNotNullParameter(action, "action");
        Intrinsics.checkNotNullParameter(parameters, "parameters");
        this.d = s;
        this.a = action;
        this.b = parameters;
        this.c = new Exception[0];
    }

    /* JADX WARN: Type inference failed for: r9v1, types: [com.facebook.internal.N] */
    public final String[] a(Void... p0) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                Intrinsics.checkNotNullParameter(p0, "p0");
                String[] stringArray = this.b.getStringArray("media");
                if (stringArray != null) {
                    final String[] strArr = new String[stringArray.length];
                    this.c = new Exception[stringArray.length];
                    final CountDownLatch countDownLatch = new CountDownLatch(stringArray.length);
                    ConcurrentLinkedQueue concurrentLinkedQueue = new ConcurrentLinkedQueue();
                    Date date = AccessToken.l;
                    AccessToken accessTokenC = com.google.android.gms.internal.mlkit_vision_common.D.c();
                    try {
                        int length = stringArray.length;
                        for (final int i = 0; i < length; i++) {
                            if (isCancelled()) {
                                Iterator it2 = concurrentLinkedQueue.iterator();
                                while (it2.hasNext()) {
                                    ((com.facebook.u) it2.next()).cancel(true);
                                }
                            } else {
                                Uri uri = Uri.parse(stringArray[i]);
                                if (J.E(uri)) {
                                    strArr[i] = uri.toString();
                                    countDownLatch.countDown();
                                } else {
                                    ?? r9 = new com.facebook.q() { // from class: com.facebook.internal.N
                                        @Override // com.facebook.q
                                        public final void a(com.facebook.w response) {
                                            FacebookRequestError facebookRequestError;
                                            String str;
                                            int i2 = i;
                                            String[] results = strArr;
                                            Intrinsics.checkNotNullParameter(results, "$results");
                                            O this$0 = this;
                                            Intrinsics.checkNotNullParameter(this$0, "this$0");
                                            CountDownLatch latch = countDownLatch;
                                            Intrinsics.checkNotNullParameter(latch, "$latch");
                                            Intrinsics.checkNotNullParameter(response, "response");
                                            try {
                                                facebookRequestError = response.c;
                                                str = "Error staging photo.";
                                            } catch (Exception e) {
                                                this$0.c[i2] = e;
                                            }
                                            if (facebookRequestError != null) {
                                                String strA = facebookRequestError.a();
                                                if (strA != null) {
                                                    str = strA;
                                                }
                                                throw new FacebookGraphResponseException(response, str);
                                            }
                                            JSONObject jSONObject = response.b;
                                            if (jSONObject == null) {
                                                throw new FacebookException("Error staging photo.");
                                            }
                                            String strOptString = jSONObject.optString("uri");
                                            if (strOptString == null) {
                                                throw new FacebookException("Error staging photo.");
                                            }
                                            results[i2] = strOptString;
                                            latch.countDown();
                                        }
                                    };
                                    Intrinsics.checkNotNullExpressionValue(uri, "uri");
                                    concurrentLinkedQueue.add(L2.h(accessTokenC, uri, r9).d());
                                }
                            }
                        }
                        countDownLatch.await();
                        return strArr;
                    } catch (Exception unused) {
                        Iterator it3 = concurrentLinkedQueue.iterator();
                        while (it3.hasNext()) {
                            ((com.facebook.u) it3.next()).cancel(true);
                        }
                    }
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }

    public final void b(String[] strArr) {
        Bundle bundle = this.b;
        S s = this.d;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            ProgressDialog progressDialog = s.e;
            if (progressDialog != null) {
                progressDialog.dismiss();
            }
            for (Exception exc : this.c) {
                if (exc != null) {
                    s.e(exc);
                    return;
                }
            }
            if (strArr == null) {
                s.e(new FacebookException("Failed to stage photos for web dialog"));
                return;
            }
            List listC = C4930v.c(strArr);
            if (listC.contains(null)) {
                s.e(new FacebookException("Failed to stage photos for web dialog"));
                return;
            }
            J.J(bundle, new JSONArray((Collection) listC));
            s.a = J.a(J.p(), com.facebook.o.d() + "/dialog/" + this.a, bundle).toString();
            ImageView imageView = s.f;
            if (imageView == null) {
                throw new IllegalStateException("Required value was null.");
            }
            s.f((imageView.getDrawable().getIntrinsicWidth() / 2) + 1);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    @Override // android.os.AsyncTask
    public final /* bridge */ /* synthetic */ Object doInBackground(Object[] objArr) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            return a((Void[]) objArr);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    @Override // android.os.AsyncTask
    public final /* bridge */ /* synthetic */ void onPostExecute(Object obj) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            b((String[]) obj);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
