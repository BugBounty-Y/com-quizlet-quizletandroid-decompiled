package androidx.appcompat.app;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.TotalCaptureResult;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.util.Range;
import android.util.SparseBooleanArray;
import androidx.appcompat.widget.ActionMenuView;
import androidx.appcompat.widget.C0087h;
import androidx.appcompat.widget.C0095l;
import androidx.camera.camera2.internal.C0135l;
import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.camera.camera2.internal.o0;
import androidx.camera.camera2.internal.s0;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.ads.A6;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.C2049fF;
import com.google.android.gms.internal.ads.C2173i7;
import com.google.android.gms.internal.ads.C2215j7;
import com.google.android.gms.internal.ads.C2301l7;
import com.google.android.gms.internal.ads.C2326lq;
import com.google.android.gms.internal.ads.C2344m7;
import com.google.android.gms.internal.ads.C2429o6;
import com.google.android.gms.internal.ads.C2815x6;
import com.google.android.gms.internal.ads.C2858y6;
import com.google.android.gms.internal.ads.G6;
import com.google.android.gms.internal.ads.Gq;
import com.google.android.gms.internal.ads.H6;
import com.google.android.gms.internal.ads.LA;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.ads.zzgzh;
import com.google.android.gms.internal.measurement.F1;
import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import com.google.android.gms.internal.play_billing.c2;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.pubmatic.sdk.video.c;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.quizletandroid.ui.common.widgets.QRichFormField;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.uicommon.ui.common.views.StatefulTintImageView;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.HttpsURLConnection;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class K implements androidx.appcompat.view.menu.y, o0, Pv, Gq, com.google.android.material.internal.s, com.google.firebase.crashlytics.internal.metadata.k, com.quizlet.uicommon.ui.common.widgets.e {
    public static K c;
    public boolean a;
    public Object b;

    public K(Uri uri, boolean z, boolean z2) {
        this.b = uri;
        this.a = z;
    }

    public static boolean H(HttpsURLConnection httpsURLConnection, String str) throws IOException {
        try {
            httpsURLConnection.setReadTimeout(c.a.DEFAULT_MEDIA_URI_TIMEOUT);
            httpsURLConnection.setConnectTimeout(c.a.DEFAULT_MEDIA_URI_TIMEOUT);
            httpsURLConnection.setDoInput(true);
            httpsURLConnection.setDoOutput(true);
            httpsURLConnection.setChunkedStreamingMode(0);
            httpsURLConnection.setRequestMethod("POST");
            httpsURLConnection.setRequestProperty("Content-Type", "application/json");
            httpsURLConnection.setRequestProperty("x-api-key", str);
            httpsURLConnection.connect();
            return true;
        } catch (IOException e) {
            Log.e("K", "Error in setting the connection parameter:", e);
            return false;
        }
    }

    public static void o(BufferedInputStream bufferedInputStream, BufferedOutputStream bufferedOutputStream, HttpsURLConnection httpsURLConnection) throws IOException {
        if (bufferedOutputStream != null) {
            try {
                bufferedOutputStream.close();
            } catch (IOException | RuntimeException e) {
                Log.e("K", "Unable to close the out stream", e);
            }
        }
        if (bufferedInputStream != null) {
            try {
                bufferedInputStream.close();
            } catch (IOException | RuntimeException e2) {
                Log.e("K", "Unable to close the in stream", e2);
            }
        }
        try {
            httpsURLConnection.disconnect();
        } catch (RuntimeException e3) {
            Log.e("K", "Unable to close the url connection", e3);
        }
    }

    public void A(int i) {
        ((com.android.billingclient.api.s) this.b).n(String.valueOf(i));
    }

    public void B(long j) {
        ((com.android.billingclient.api.s) this.b).n(String.valueOf(j));
    }

    public void C(String v) {
        Intrinsics.checkNotNullParameter(v, "v");
        ((com.android.billingclient.api.s) this.b).n(v);
    }

    public void D(short s) {
        ((com.android.billingclient.api.s) this.b).n(String.valueOf(s));
    }

    public void E(String text) {
        byte b;
        Intrinsics.checkNotNullParameter(text, "value");
        com.android.billingclient.api.s sVar = (com.android.billingclient.api.s) this.b;
        Intrinsics.checkNotNullParameter(text, "text");
        sVar.j(sVar.b, text.length() + 2);
        char[] cArr = (char[]) sVar.c;
        int i = sVar.b;
        int i2 = i + 1;
        cArr[i] = '\"';
        int length = text.length();
        text.getChars(0, length, cArr, i2);
        int i3 = length + i2;
        int i4 = i2;
        while (i4 < i3) {
            char c2 = cArr[i4];
            byte[] bArr = kotlinx.serialization.json.internal.x.b;
            if (c2 < bArr.length && bArr[c2] != 0) {
                int length2 = text.length();
                for (int i5 = i4 - i2; i5 < length2; i5++) {
                    sVar.j(i4, 2);
                    char cCharAt = text.charAt(i5);
                    byte[] bArr2 = kotlinx.serialization.json.internal.x.b;
                    if (cCharAt >= bArr2.length || (b = bArr2[cCharAt]) == 0) {
                        int i6 = i4 + 1;
                        ((char[]) sVar.c)[i4] = cCharAt;
                        i4 = i6;
                    } else {
                        if (b == 1) {
                            String str = kotlinx.serialization.json.internal.x.a[cCharAt];
                            Intrinsics.d(str);
                            sVar.j(i4, str.length());
                            str.getChars(0, str.length(), (char[]) sVar.c, i4);
                            int length3 = str.length() + i4;
                            sVar.b = length3;
                            i4 = length3;
                        } else {
                            char[] cArr2 = (char[]) sVar.c;
                            cArr2[i4] = '\\';
                            cArr2[i4 + 1] = (char) b;
                            i4 += 2;
                            sVar.b = i4;
                        }
                    }
                }
                sVar.j(i4, 1);
                ((char[]) sVar.c)[i4] = '\"';
                sVar.b = i4 + 1;
                return;
            }
            i4++;
        }
        cArr[i3] = '\"';
        sVar.b = i3 + 1;
    }

    public synchronized void F(com.bumptech.glide.load.engine.v vVar, boolean z) {
        try {
            if (this.a || z) {
                ((Handler) this.b).obtainMessage(1, vVar).sendToTarget();
            } else {
                this.a = true;
                vVar.recycle();
                this.a = false;
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    public void G(String str, String str2, String str3) {
        androidx.camera.camera2.internal.compat.b bVar = new androidx.camera.camera2.internal.compat.b(this, str, str2, str3, 5);
        synchronized (this) {
            try {
            } catch (InternalError e) {
                Log.e("K", "Internal error in executing the thread", e);
                if (e.getLocalizedMessage().contains("shutdown")) {
                    Log.e("K", "Got the shutdown signal", e);
                }
            } catch (RuntimeException e2) {
                Log.e("K", "Error running the thread", e2);
            }
            if (!this.a) {
                ((ExecutorService) this.b).execute(bVar);
            }
        }
    }

    public void I() {
    }

    public void J() {
        LinkedList linkedList = new LinkedList((List) this.b);
        while (!linkedList.isEmpty()) {
            com.google.common.util.concurrent.e eVar = (com.google.common.util.concurrent.e) linkedList.poll();
            Objects.requireNonNull(eVar);
            eVar.cancel(true);
        }
    }

    public void K() {
    }

    public void L(int i) {
        AbstractC1795We.L(!this.a);
        ((SparseBooleanArray) this.b).append(i, true);
    }

    public void M(c2 c2Var) {
        if (this.a) {
            AbstractC3819n0.f("BillingLogger", "Skipping logging since initialization failed.");
            return;
        }
        try {
            ((com.google.android.datatransport.runtime.p) this.b).a(new com.google.android.datatransport.a(c2Var, com.google.android.datatransport.d.a, null), new com.facebook.appevents.k(16));
        } catch (Throwable unused) {
            AbstractC3819n0.f("BillingLogger", "logging failed.");
        }
    }

    public C2049fF N() {
        AbstractC1795We.L(!this.a);
        this.a = true;
        return new C2049fF((SparseBooleanArray) this.b);
    }

    public F1 O(long j, String str) {
        Long lValueOf = Long.valueOf(j);
        Object obj = F1.g;
        return new F1(this, str, lValueOf, 0);
    }

    public F1 P(String str, String str2) {
        Object obj = F1.g;
        return new F1(this, str, str2, 3);
    }

    public F1 Q(String str, boolean z) {
        Boolean boolValueOf = Boolean.valueOf(z);
        Object obj = F1.g;
        return new F1(this, str, boolValueOf, 1);
    }

    @Override // com.google.firebase.crashlytics.internal.metadata.k
    public void a(com.google.firebase.crashlytics.internal.metadata.j jVar, int i) {
        boolean z = this.a;
        StringBuilder sb = (StringBuilder) this.b;
        if (z) {
            this.a = false;
        } else {
            sb.append(", ");
        }
        sb.append(i);
    }

    @Override // com.google.android.gms.internal.ads.Gq
    public Object b(Object obj) {
        long j;
        C2326lq c2326lq = (C2326lq) this.b;
        SQLiteDatabase sQLiteDatabase = (SQLiteDatabase) obj;
        if (this.a) {
            ((Context) c2326lq.b).deleteDatabase("OfflineUpload.db");
            return null;
        }
        ArrayList arrayList = new ArrayList();
        Cursor cursorQuery = sQLiteDatabase.query("offline_signal_contents", new String[]{"serialized_proto_data"}, null, null, null, null, null);
        while (cursorQuery.moveToNext()) {
            try {
                arrayList.add(C2815x6.M(cursorQuery.getBlob(cursorQuery.getColumnIndexOrThrow("serialized_proto_data"))));
            } catch (zzgzh e) {
                com.google.android.gms.ads.internal.util.client.i.e("Unable to deserialize proto from offline signals database:");
                com.google.android.gms.ads.internal.util.client.i.e(e.getMessage());
            }
        }
        cursorQuery.close();
        Context context = (Context) c2326lq.b;
        C2858y6 c2858y6E = A6.E();
        String packageName = context.getPackageName();
        c2858y6E.e();
        A6.x((A6) c2858y6E.b, packageName);
        String str = Build.MODEL;
        c2858y6E.e();
        A6.z((A6) c2858y6E.b);
        int iA = LA.a(sQLiteDatabase, 0);
        c2858y6E.e();
        A6.A((A6) c2858y6E.b, iA);
        c2858y6E.e();
        A6.w((A6) c2858y6E.b, arrayList);
        int iA2 = LA.a(sQLiteDatabase, 1);
        c2858y6E.e();
        A6.C((A6) c2858y6E.b, iA2);
        int iA3 = LA.a(sQLiteDatabase, 3);
        c2858y6E.e();
        A6.y((A6) c2858y6E.b, iA3);
        com.google.android.gms.ads.internal.j.C.k.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        c2858y6E.e();
        A6.D((A6) c2858y6E.b, jCurrentTimeMillis);
        Cursor cursorD = LA.D(sQLiteDatabase, 2);
        if (cursorD.getCount() > 0) {
            cursorD.moveToNext();
            j = cursorD.getLong(cursorD.getColumnIndexOrThrow("value"));
        } else {
            j = 0;
        }
        cursorD.close();
        c2858y6E.e();
        A6.B((A6) c2858y6E.b, j);
        A6 a6 = (A6) c2858y6E.c();
        int size = arrayList.size();
        long J = 0;
        for (int i = 0; i < size; i++) {
            C2815x6 c2815x6 = (C2815x6) arrayList.get(i);
            if (c2815x6.K() == 2 && c2815x6.J() > J) {
                J = c2815x6.J();
            }
        }
        if (J != 0) {
            ContentValues contentValues = new ContentValues();
            contentValues.put("value", Long.valueOf(J));
            sQLiteDatabase.update("offline_signal_statistics", contentValues, "statistic_name = 'last_successful_request_time'", null);
        }
        C2429o6 c2429o6 = (C2429o6) c2326lq.c;
        synchronized (c2429o6) {
            if (c2429o6.c) {
                try {
                    C2301l7 c2301l7 = c2429o6.b;
                    c2301l7.e();
                    C2344m7.B((C2344m7) c2301l7.b, a6);
                } catch (NullPointerException e2) {
                    com.google.android.gms.ads.internal.j.C.h.h("AdMobClearcutLogger.modify", e2);
                }
            }
            VersionInfoParcel versionInfoParcel = (VersionInfoParcel) c2326lq.d;
            G6 g6Z = H6.z();
            int i2 = versionInfoParcel.b;
            g6Z.e();
            H6.w((H6) g6Z.b, i2);
            int i3 = versionInfoParcel.c;
            g6Z.e();
            H6.y((H6) g6Z.b, i3);
            int i4 = true != versionInfoParcel.d ? 2 : 0;
            g6Z.e();
            H6.x((H6) g6Z.b, i4);
            H6 h6 = (H6) g6Z.c();
            synchronized (c2429o6) {
                if (c2429o6.c) {
                    try {
                        C2301l7 c2301l72 = c2429o6.b;
                        C2173i7 c2173i7 = (C2173i7) ((C2344m7) c2301l72.b).G().l();
                        c2173i7.e();
                        C2215j7.x((C2215j7) c2173i7.b, h6);
                        c2301l72.e();
                        C2344m7.A((C2344m7) c2301l72.b, (C2215j7) c2173i7.c());
                    } catch (NullPointerException e3) {
                        com.google.android.gms.ads.internal.j.C.h.h("AdMobClearcutLogger.modify", e3);
                    }
                }
                c2429o6.b(10004);
                sQLiteDatabase.delete("offline_signal_contents", null, null);
                LA.I(sQLiteDatabase, "failed_requests");
                LA.I(sQLiteDatabase, "total_requests");
                LA.I(sQLiteDatabase, "completed_requests");
                return null;
            }
        }
        c2429o6.b(10004);
        sQLiteDatabase.delete("offline_signal_contents", null, null);
        LA.I(sQLiteDatabase, "failed_requests");
        LA.I(sQLiteDatabase, "total_requests");
        LA.I(sQLiteDatabase, "completed_requests");
        return null;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x009b  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00b6 A[SYNTHETIC] */
    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo15c(java.lang.Object r12) {
        /*
            Method dump skipped, instructions count: 368
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.K.mo15c(java.lang.Object):void");
    }

    @Override // androidx.camera.camera2.internal.o0
    public void d(TotalCaptureResult totalCaptureResult) {
    }

    @Override // androidx.appcompat.view.menu.y
    public void e(androidx.appcompat.view.menu.n nVar, boolean z) {
        C0095l c0095l;
        if (this.a) {
            return;
        }
        this.a = true;
        M m = (M) this.b;
        ActionMenuView actionMenuView = m.a.a.a;
        if (actionMenuView != null && (c0095l = actionMenuView.t) != null) {
            c0095l.f();
            C0087h c0087h = c0095l.t;
            if (c0087h != null && c0087h.b()) {
                c0087h.i.dismiss();
            }
        }
        m.b.onPanelClosed(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY, nVar);
        this.a = false;
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public boolean f(QFormField formField) {
        Intrinsics.checkNotNullParameter(formField, "formField");
        return this.a;
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public CharSequence g(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        String string = context.getString(R.string.upload_image_for_current_term);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        return string;
    }

    @Override // androidx.camera.camera2.internal.o0
    public void h(androidx.camera.camera2.impl.a options) {
        CaptureRequest.Key key = CaptureRequest.CONTROL_ZOOM_RATIO;
        Float fValueOf = Float.valueOf(1.0f);
        androidx.camera.core.impl.G priority = androidx.camera.core.impl.G.b;
        options.a(key, fValueOf);
        if (this.a) {
            Intrinsics.checkNotNullParameter(options, "options");
            Intrinsics.checkNotNullParameter(priority, "priority");
            if (Build.VERSION.SDK_INT >= 34) {
                options.a(CaptureRequest.CONTROL_SETTINGS_OVERRIDE, 1);
            }
        }
    }

    @Override // androidx.camera.camera2.internal.o0
    public float i() {
        return ((Float) ((Range) this.b).getUpper()).floatValue();
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public void j(QFormField formField) {
        Intrinsics.checkNotNullParameter(formField, "formField");
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x007c  */
    @Override // com.google.android.material.internal.s
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public androidx.core.view.D0 k(android.view.View r11, androidx.core.view.D0 r12, com.google.android.gms.ads.internal.overlay.k r13) {
        /*
            r10 = this;
            androidx.core.view.z0 r0 = r12.a
            r1 = 519(0x207, float:7.27E-43)
            androidx.core.graphics.e r1 = r0.g(r1)
            r2 = 32
            androidx.core.graphics.e r0 = r0.g(r2)
            int r2 = r1.b
            java.lang.Object r3 = r10.b
            com.google.android.material.bottomsheet.BottomSheetBehavior r3 = (com.google.android.material.bottomsheet.BottomSheetBehavior) r3
            r3.w = r2
            boolean r2 = com.google.android.material.internal.p.k(r11)
            int r4 = r11.getPaddingBottom()
            int r5 = r11.getPaddingLeft()
            int r6 = r11.getPaddingRight()
            boolean r7 = r3.o
            if (r7 == 0) goto L33
            int r4 = r12.a()
            r3.v = r4
            int r7 = r13.d
            int r4 = r4 + r7
        L33:
            boolean r7 = r3.p
            int r8 = r1.a
            if (r7 == 0) goto L41
            if (r2 == 0) goto L3e
            int r5 = r13.c
            goto L40
        L3e:
            int r5 = r13.a
        L40:
            int r5 = r5 + r8
        L41:
            boolean r7 = r3.q
            int r9 = r1.c
            if (r7 == 0) goto L50
            if (r2 == 0) goto L4c
            int r13 = r13.a
            goto L4e
        L4c:
            int r13 = r13.c
        L4e:
            int r6 = r13 + r9
        L50:
            android.view.ViewGroup$LayoutParams r13 = r11.getLayoutParams()
            android.view.ViewGroup$MarginLayoutParams r13 = (android.view.ViewGroup.MarginLayoutParams) r13
            boolean r2 = r3.s
            r7 = 1
            if (r2 == 0) goto L63
            int r2 = r13.leftMargin
            if (r2 == r8) goto L63
            r13.leftMargin = r8
            r2 = r7
            goto L64
        L63:
            r2 = 0
        L64:
            boolean r8 = r3.t
            if (r8 == 0) goto L6f
            int r8 = r13.rightMargin
            if (r8 == r9) goto L6f
            r13.rightMargin = r9
            r2 = r7
        L6f:
            boolean r8 = r3.u
            if (r8 == 0) goto L7c
            int r8 = r13.topMargin
            int r1 = r1.b
            if (r8 == r1) goto L7c
            r13.topMargin = r1
            goto L7d
        L7c:
            r7 = r2
        L7d:
            if (r7 == 0) goto L82
            r11.setLayoutParams(r13)
        L82:
            int r13 = r11.getPaddingTop()
            r11.setPadding(r5, r13, r6, r4)
            boolean r11 = r10.a
            if (r11 == 0) goto L91
            int r13 = r0.d
            r3.m = r13
        L91:
            boolean r13 = r3.o
            if (r13 != 0) goto L99
            if (r11 == 0) goto L98
            goto L99
        L98:
            return r12
        L99:
            r3.Q()
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.K.k(android.view.View, androidx.core.view.D0, com.google.android.gms.ads.internal.overlay.k):androidx.core.view.D0");
    }

    @Override // androidx.camera.camera2.internal.o0
    public float l() {
        return ((Float) ((Range) this.b).getLower()).floatValue();
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public void m(QFormField formField, StatefulTintImageView view) {
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar;
        Intrinsics.checkNotNullParameter(formField, "formField");
        Intrinsics.checkNotNullParameter(view, "view");
        com.quizlet.quizletandroid.ui.setcreation.viewholders.m mVar = ((com.quizlet.quizletandroid.ui.setcreation.viewholders.l) ((C4636c) this.b).b).k;
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = mVar.i;
        int adapterPosition = mVar.getAdapterPosition();
        QRichFormField anchor = mVar.f();
        fVar.m();
        DBTerm term = fVar.j(adapterPosition);
        if (term != null && (aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar.r.get()) != null) {
            EditSetFragment editSetFragment = (EditSetFragment) aVar;
            Intrinsics.checkNotNullParameter(term, "term");
            Intrinsics.checkNotNullParameter(anchor, "anchor");
            com.quizlet.data.repository.explanations.question.a aVar2 = editSetFragment.s;
            if (aVar2 == null) {
                Intrinsics.m("imageUploadFeatureWrapper");
                throw null;
            }
            io.reactivex.rxjava3.core.p pVarL = ((assistantMode.utils.studiableMetadata.b) aVar2.a).L((androidx.work.impl.model.c) aVar2.c);
            com.quizlet.data.repository.explanations.question.a aVar3 = editSetFragment.s;
            if (aVar3 == null) {
                Intrinsics.m("imageUploadFeatureWrapper");
                throw null;
            }
            io.reactivex.rxjava3.core.p.p(pVarL, ((com.google.android.material.floatingactionbutton.c) aVar3.b).o((androidx.work.impl.model.c) aVar3.c), com.quizlet.quizletandroid.ui.setcreation.fragments.d.a).i(new com.quizlet.billing.manager.b(14, editSetFragment, term), com.quizlet.quizletandroid.ui.setcreation.fragments.e.b);
        }
        EventLogger eventLogger = mVar.d;
        if (eventLogger != null) {
            eventLogger.I("studymode_interstitial_dismissed");
        } else {
            Intrinsics.m("eventLogger");
            throw null;
        }
    }

    @Override // com.quizlet.uicommon.ui.common.widgets.e
    public int n() {
        return R.drawable.ic_sys_camera;
    }

    public CameraCaptureSession.CaptureCallback p(CameraCaptureSession.CaptureCallback captureCallback) {
        int i = 2;
        if (!this.a) {
            return captureCallback;
        }
        C0135l c0135l = new C0135l(3);
        List list = (List) this.b;
        androidx.concurrent.futures.l lVar = (androidx.concurrent.futures.l) c0135l.b;
        list.add(lVar);
        lVar.b.a(new RunnableC0130g(this, c0135l, lVar, i), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
        return new androidx.camera.camera2.internal.G(Arrays.asList(c0135l, captureCallback));
    }

    public boolean q() {
        return this.a;
    }

    public com.google.common.util.concurrent.e r() {
        List list = (List) this.b;
        if (list.isEmpty()) {
            return androidx.camera.core.impl.utils.futures.k.c;
        }
        androidx.camera.core.impl.utils.futures.l lVar = new androidx.camera.core.impl.utils.futures.l(new ArrayList(new ArrayList(list)), false, com.google.android.gms.internal.mlkit_vision_barcode.T.a());
        s0 s0Var = new s0(1);
        return androidx.camera.core.impl.utils.futures.i.d(androidx.camera.core.impl.utils.futures.i.f(lVar, new com.google.android.gms.auth.api.signin.internal.h(s0Var, 7), com.google.android.gms.internal.mlkit_vision_barcode.T.a()));
    }

    public void s() {
        this.a = true;
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0036  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0038  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean t(java.lang.CharSequence r6, int r7, int r8) {
        /*
            r5 = this;
            r0 = 1
            if (r6 == 0) goto L46
            if (r7 < 0) goto L46
            if (r8 < 0) goto L46
            int r1 = r6.length()
            int r1 = r1 - r8
            if (r1 < r7) goto L46
            java.lang.Object r1 = r5.b
            androidx.core.text.e r1 = (androidx.core.text.e) r1
            if (r1 != 0) goto L19
            boolean r6 = r5.q()
            return r6
        L19:
            int r8 = r8 + r7
            r1 = 2
            r2 = r1
        L1c:
            r3 = 0
            if (r7 >= r8) goto L3b
            if (r2 != r1) goto L3b
            char r2 = r6.charAt(r7)
            byte r2 = java.lang.Character.getDirectionality(r2)
            androidx.appcompat.app.K r4 = androidx.core.text.f.a
            if (r2 == 0) goto L38
            if (r2 == r0) goto L36
            if (r2 == r1) goto L36
            switch(r2) {
                case 14: goto L38;
                case 15: goto L38;
                case 16: goto L36;
                case 17: goto L36;
                default: goto L34;
            }
        L34:
            r2 = r1
            goto L39
        L36:
            r2 = r3
            goto L39
        L38:
            r2 = r0
        L39:
            int r7 = r7 + r0
            goto L1c
        L3b:
            if (r2 == 0) goto L45
            if (r2 == r0) goto L44
            boolean r6 = r5.q()
            return r6
        L44:
            return r3
        L45:
            return r0
        L46:
            java.lang.IllegalArgumentException r6 = new java.lang.IllegalArgumentException
            r6.<init>()
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.K.t(java.lang.CharSequence, int, int):boolean");
    }

    public void u() {
        this.a = false;
    }

    public void v() {
        this.a = false;
    }

    public void w(byte b) {
        ((com.android.billingclient.api.s) this.b).n(String.valueOf(b));
    }

    public void x(char c2) {
        com.android.billingclient.api.s sVar = (com.android.billingclient.api.s) this.b;
        sVar.j(sVar.b, 1);
        char[] cArr = (char[]) sVar.c;
        int i = sVar.b;
        sVar.b = i + 1;
        cArr[i] = c2;
    }

    @Override // androidx.camera.camera2.internal.o0
    public void y() {
    }

    @Override // androidx.appcompat.view.menu.y
    public boolean z(androidx.appcompat.view.menu.n nVar) {
        ((M) this.b).b.onMenuOpened(OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY, nVar);
        return true;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        com.google.android.gms.ads.internal.util.client.i.e("Failed to get signals bundle");
    }

    public /* synthetic */ K(Object obj) {
        this.b = obj;
    }

    public /* synthetic */ K(Object obj, boolean z) {
        this.a = z;
        this.b = obj;
    }

    public K(com.android.billingclient.api.s writer) {
        Intrinsics.checkNotNullParameter(writer, "writer");
        this.b = writer;
        this.a = true;
    }

    public K(int i) {
        switch (i) {
            case 7:
                this.b = new Handler(Looper.getMainLooper(), new com.bumptech.glide.load.engine.y(0));
                break;
            case 10:
                this.b = new SparseBooleanArray();
                break;
            case 16:
                io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
                Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
                this.b = dVarZ;
                break;
            default:
                this.b = Executors.newFixedThreadPool(2);
                this.a = false;
                Runtime.getRuntime().addShutdownHook(new com.amazon.aps.shared.util.a(this, 0));
                break;
        }
    }

    public K(boolean z) {
        this.b = Collections.synchronizedList(new ArrayList());
        this.a = z;
    }

    public K(androidx.core.text.e eVar, boolean z) {
        this(eVar);
        this.a = z;
    }
}
