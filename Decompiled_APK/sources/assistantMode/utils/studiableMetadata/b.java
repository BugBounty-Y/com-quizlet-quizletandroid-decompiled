package assistantMode.utils.studiableMetadata;

import android.animation.ValueAnimator;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Insets;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.text.Html;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.method.LinkMovementMethod;
import android.text.style.URLSpan;
import android.util.DisplayMetrics;
import android.util.Log;
import android.util.Pair;
import android.util.Size;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowMetrics;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.appcompat.widget.o1;
import androidx.camera.camera2.internal.c0;
import androidx.compose.animation.d0;
import androidx.compose.ui.text.font.u;
import androidx.compose.ui.text.font.z;
import androidx.compose.ui.text.input.C;
import androidx.constraintlayout.motion.widget.n;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import androidx.work.impl.constraints.m;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.bumptech.glide.manager.g;
import com.bumptech.glide.manager.i;
import com.facebook.AccessToken;
import com.facebook.FacebookException;
import com.facebook.GraphRequest$ParcelableResourceWithMimeType;
import com.facebook.f;
import com.facebook.internal.A;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.J;
import com.facebook.o;
import com.facebook.p;
import com.facebook.q;
import com.facebook.s;
import com.facebook.t;
import com.facebook.v;
import com.facebook.x;
import com.facebook.y;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.j;
import com.google.android.gms.ads.internal.overlay.AdOverlayInfoParcel;
import com.google.android.gms.ads.internal.overlay.zzc;
import com.google.android.gms.ads.internal.util.F;
import com.google.android.gms.cloudmessaging.k;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.Hk;
import com.google.android.gms.internal.ads.InterfaceC2447oi;
import com.google.android.gms.internal.measurement.B3;
import com.google.android.gms.internal.measurement.D3;
import com.google.android.gms.internal.measurement.E3;
import com.google.android.gms.internal.measurement.G3;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.measurement.W3;
import com.google.android.gms.internal.measurement.Y3;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5;
import com.google.android.gms.internal.mlkit_vision_common.G;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3605e0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.P;
import com.google.android.gms.measurement.internal.A0;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.Z;
import com.google.android.gms.measurement.internal.r;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.h;
import com.google.firebase.components.d;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.OTThemeConstants;
import com.quizlet.data.model.User;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.notes.detail.MagicNotesDetailActivity;
import com.quizlet.local.ormlite.util.c;
import com.quizlet.quizletandroid.R;
import java.io.BufferedOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.ReferenceQueue;
import java.lang.reflect.Array;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.GZIPOutputStream;
import kotlin.coroutines.l;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class b implements a, z, l, g, r, d, com.google.zxing.b, com.perimeterx.mobile_sdk.doctor_app.state.d, c {
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    public static void A(JSONArray jSONArray, JSONObject jSONObject) throws JSONException {
        if (jSONObject.has("SubGroups")) {
            JSONArray jSONArray2 = new JSONArray();
            JSONArray jSONArray3 = jSONObject.getJSONArray("SubGroups");
            for (int i = 0; i < jSONArray3.length(); i++) {
                if (!jSONArray3.getJSONObject(i).getString("Type").contains("COOKIE")) {
                    jSONArray2.put(jSONArray3.getJSONObject(i));
                }
            }
            for (int i2 = 0; i2 < jSONArray2.length(); i2++) {
                JSONObject jSONObject2 = new JSONObject();
                JSONObject jSONObject3 = jSONArray2.getJSONObject(i2);
                if (!"IAB2_STACK".equals(jSONObject3.getString("Type")) && !"IAB2V2_STACK".equals(jSONObject3.getString("Type")) && !jSONObject3.getString("Type").contains("COOKIE") && !jSONObject3.getString("Type").contains("BRANCH")) {
                    jSONObject2.put("CustomGroupId", jSONObject3.optString("CustomGroupId", ""));
                    jSONObject2.put("GroupName", jSONObject3.optString("GroupName", ""));
                    jSONObject2.put("Type", jSONObject3.optString("Type", ""));
                    jSONArray.put(jSONObject2);
                }
            }
        }
    }

    public static boolean B(JSONObject jSONObject) throws JSONException {
        JSONArray jSONArray;
        if (jSONObject.has("IabIllustrations")) {
            try {
                jSONArray = jSONObject.getJSONArray("IabIllustrations");
            } catch (JSONException e) {
                Z.p("Error on getting iab illustration array. Error = ", e, "UIUtils", 6);
            }
        } else {
            jSONArray = null;
        }
        return jSONArray != null && jSONArray.length() > 0;
    }

    public static final String C(Object obj) {
        String str = t.j;
        if (obj instanceof String) {
            return (String) obj;
        }
        if ((obj instanceof Boolean) || (obj instanceof Number)) {
            return obj.toString();
        }
        if (!(obj instanceof Date)) {
            throw new IllegalArgumentException("Unsupported parameter type.");
        }
        String str2 = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ", Locale.US).format((Date) obj);
        Intrinsics.checkNotNullExpressionValue(str2, "iso8601DateFormat.format(value)");
        return str2;
    }

    public static void D(JSONObject jSONObject, boolean z) {
        if (z) {
            if (jSONObject.has("BannerMPButtonColor")) {
                return;
            }
            OTLogger.c("OneTrust", 6, "Downloaded data does not contain the required fields to render the UI. \nPlease publish the application to a version that matches the SDK version from the admin UI.");
        } else {
            if (jSONObject.has("IsIabEnabled") && jSONObject.has("PCGrpDescType") && jSONObject.has("BConsentText")) {
                return;
            }
            OTLogger.c("OneTrust", 6, "Downloaded data does not contain the required fields to render the UI. \nPlease publish the application to a version that matches the SDK version from the admin UI.");
        }
    }

    public static com.google.zxing.common.b E(byte[][] bArr, int i) {
        int i2 = i * 2;
        int length = bArr[0].length + i2;
        int length2 = bArr.length + i2;
        com.google.zxing.common.b bVar = new com.google.zxing.common.b(length, length2);
        int[] iArr = bVar.d;
        int length3 = iArr.length;
        for (int i3 = 0; i3 < length3; i3++) {
            iArr[i3] = 0;
        }
        int i4 = (length2 - i) - 1;
        int i5 = 0;
        while (i5 < bArr.length) {
            byte[] bArr2 = bArr[i5];
            for (int i6 = 0; i6 < bArr[0].length; i6++) {
                if (bArr2[i6] == 1) {
                    bVar.c(i6 + i, i4);
                }
            }
            i5++;
            i4--;
        }
        return bVar;
    }

    public static Typeface F(String str, u uVar, int i) {
        if (i == 0 && Intrinsics.b(uVar, u.f) && (str == null || str.length() == 0)) {
            return Typeface.DEFAULT;
        }
        int iC = AbstractC3249r5.c(uVar, i);
        return (str == null || str.length() == 0) ? Typeface.defaultFromStyle(iC) : Typeface.create(str, iC);
    }

    public static HttpURLConnection G(URL url) {
        URLConnection uRLConnection = (URLConnection) FirebasePerfUrlConnection.instrument(url.openConnection());
        Intrinsics.e(uRLConnection, "null cannot be cast to non-null type java.net.HttpURLConnection");
        HttpURLConnection httpURLConnection = (HttpURLConnection) uRLConnection;
        if (t.l == null) {
            t.l = d0.s(new Object[]{"FBAndroidSDK", "18.0.3"}, 2, "%s.%s", "format(format, *args)");
        }
        httpURLConnection.setRequestProperty("User-Agent", t.l);
        httpURLConnection.setRequestProperty("Accept-Language", Locale.getDefault().toString());
        httpURLConnection.setChunkedStreamingMode(0);
        return httpURLConnection;
    }

    public static ArrayList H(v requests) throws Throwable {
        Exception exc;
        HttpURLConnection httpURLConnectionZ;
        ArrayList arrayListI;
        Intrinsics.checkNotNullParameter(requests, "requests");
        AbstractC1554i.i(requests);
        HttpURLConnection httpURLConnection = null;
        try {
            httpURLConnectionZ = Z(requests);
            exc = null;
        } catch (Exception e) {
            exc = e;
            httpURLConnectionZ = null;
        } catch (Throwable th) {
            th = th;
            J.k(httpURLConnection);
            throw th;
        }
        try {
            if (httpURLConnectionZ != null) {
                arrayListI = I(requests, httpURLConnectionZ);
            } else {
                ArrayList arrayListA = G.a(requests.c, null, new FacebookException(exc));
                W(requests, arrayListA);
                arrayListI = arrayListA;
            }
            J.k(httpURLConnectionZ);
            return arrayListI;
        } catch (Throwable th2) {
            th = th2;
            httpURLConnection = httpURLConnectionZ;
            J.k(httpURLConnection);
            throw th;
        }
    }

    public static ArrayList I(v requests, HttpURLConnection connection) {
        ArrayList arrayListA;
        Intrinsics.checkNotNullParameter(connection, "connection");
        Intrinsics.checkNotNullParameter(requests, "requests");
        y yVar = y.a;
        Intrinsics.checkNotNullParameter(connection, "connection");
        Intrinsics.checkNotNullParameter(requests, "requests");
        InputStream errorStream = null;
        try {
            try {
            } catch (FacebookException e) {
                com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
                com.google.mlkit.common.sdkinternal.model.a.w(yVar, "Response", "Response <Error>: %s", e);
                arrayListA = G.a(requests, connection, e);
            } catch (Exception e2) {
                com.google.mlkit.common.sdkinternal.model.a aVar2 = A.c;
                com.google.mlkit.common.sdkinternal.model.a.w(yVar, "Response", "Response <Error>: %s", e2);
                arrayListA = G.a(requests, connection, new FacebookException(e2));
            }
            if (!o.g()) {
                Log.e("com.facebook.w", "GraphRequest can't be used when Facebook SDK isn't fully initialized");
                throw new FacebookException("GraphRequest can't be used when Facebook SDK isn't fully initialized");
            }
            errorStream = connection.getResponseCode() >= 400 ? connection.getErrorStream() : connection.getInputStream();
            arrayListA = G.c(errorStream, connection, requests);
            J.d(errorStream);
            connection.disconnect();
            int size = requests.c.size();
            if (size != arrayListA.size()) {
                String str = String.format(Locale.US, "Received %d responses while expecting %d", Arrays.copyOf(new Object[]{Integer.valueOf(arrayListA.size()), Integer.valueOf(size)}, 2));
                Intrinsics.checkNotNullExpressionValue(str, "format(locale, format, *args)");
                throw new FacebookException(str);
            }
            W(requests, arrayListA);
            f fVarO = f.f.o();
            AccessToken accessToken = fVarO.c;
            if (accessToken != null) {
                long jF = assistantMode.refactored.a.f();
                if (accessToken.f.a && jF - fVarO.e.getTime() > 3600000 && jF - accessToken.g.getTime() > 86400000) {
                    if (Intrinsics.b(Looper.getMainLooper(), Looper.myLooper())) {
                        fVarO.a();
                    } else {
                        new Handler(Looper.getMainLooper()).post(new C(fVarO, 15));
                    }
                }
            }
            return arrayListA;
        } catch (Throwable th) {
            J.d(null);
            throw th;
        }
    }

    public static Intent J(Context context, String noteUuid, boolean z, AddMaterialFolderData addMaterialFolderData) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(noteUuid, "noteUuid");
        Intent intent = new Intent(context, (Class<?>) MagicNotesDetailActivity.class);
        intent.putExtra("uuid", noteUuid);
        intent.putExtra("displayFlashcardsOnly", z);
        intent.putExtra("addMaterialFolderData", addMaterialFolderData);
        return intent;
    }

    /* JADX WARN: Code restructure failed: missing block: B:31:0x0045, code lost:
    
        if (java.lang.Character.isHighSurrogate(r5) != false) goto L33;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0082, code lost:
    
        if (java.lang.Character.isLowSurrogate(r5) != false) goto L58;
     */
    /* JADX WARN: Removed duplicated region for block: B:46:0x006c A[EDGE_INSN: B:92:0x006c->B:46:0x006c BREAK  A[LOOP:2: B:47:0x006e->B:58:0x0085], EDGE_INSN: B:93:0x006c->B:46:0x006c BREAK  A[LOOP:2: B:47:0x006e->B:58:0x0085, LOOP_LABEL: LOOP:2: B:47:0x006e->B:58:0x0085]] */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00a2 A[ADDED_TO_REGION] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean K(androidx.emoji2.viewsintegration.b r7, android.text.Editable r8, int r9, int r10, boolean r11) {
        /*
            Method dump skipped, instructions count: 240
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.utils.studiableMetadata.b.K(androidx.emoji2.viewsintegration.b, android.text.Editable, int, int, boolean):boolean");
    }

    public static boolean M(Object obj) {
        return (obj instanceof Bitmap) || (obj instanceof byte[]) || (obj instanceof Uri) || (obj instanceof ParcelFileDescriptor) || (obj instanceof GraphRequest$ParcelableResourceWithMimeType);
    }

    public static boolean N(Object obj) {
        return (obj instanceof String) || (obj instanceof Boolean) || (obj instanceof Number) || (obj instanceof Date);
    }

    public static User O(DBUser local) {
        Intrinsics.checkNotNullParameter(local, "local");
        long id = local.getId();
        String username = local.getUsername();
        if (username == null) {
            username = "";
        }
        long timestamp = local.getTimestamp();
        long lastModified = local.getLastModified();
        int userUpgradeType = local.getUserUpgradeType();
        int selfIdentifiedUserType = local.getSelfIdentifiedUserType();
        boolean isLocked = local.getIsLocked();
        String imageUrl = local.getImageUrl();
        return new User(id, username, timestamp, lastModified, local.getIsVerified(), userUpgradeType, selfIdentifiedUserType, isLocked, imageUrl == null ? "" : imageUrl, local.getTimeZone(), local.getProfileImageId(), local.getDeleted(), null, null, null, 16384, null);
    }

    public static DBUser P(User data) {
        Intrinsics.checkNotNullParameter(data, "data");
        DBUser dBUser = new DBUser();
        dBUser.setId(data.a);
        dBUser.setUsername(data.b);
        dBUser.setTimestamp((int) data.c);
        dBUser.setLastModified(data.d);
        dBUser.setUserUpgradeType(data.f);
        dBUser.setSelfIdentifiedUserType(data.g);
        dBUser.setIsLocked(data.h);
        dBUser.setImageUrl(data.i);
        dBUser.setTimeZone(data.j);
        dBUser.setProfileImageId(data.k);
        dBUser.setIsVerified(data.e);
        dBUser.setDeleted(data.l);
        return dBUser;
    }

    public static t Q(AccessToken accessToken, String str, q qVar) {
        return new t(accessToken, str, null, null, qVar);
    }

    public static t R(AccessToken accessToken, String str, JSONObject jSONObject, q qVar) {
        t tVar = new t(accessToken, str, null, x.b, qVar);
        tVar.c = jSONObject;
        return tVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x002a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void S(org.json.JSONObject r7, java.lang.String r8, com.facebook.s r9) {
        /*
            java.util.regex.Pattern r0 = com.facebook.t.k
            java.util.regex.Matcher r0 = r0.matcher(r8)
            boolean r1 = r0.matches()
            r2 = 1
            if (r1 == 0) goto L17
            java.lang.String r0 = r0.group(r2)
            java.lang.String r1 = "matcher.group(1)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r1)
            goto L18
        L17:
            r0 = r8
        L18:
            java.lang.String r1 = "me/"
            r3 = 0
            boolean r1 = kotlin.text.D.r(r0, r1, r3)
            if (r1 != 0) goto L2c
            java.lang.String r1 = "/me/"
            boolean r0 = kotlin.text.D.r(r0, r1, r3)
            if (r0 == 0) goto L2a
            goto L2c
        L2a:
            r8 = r3
            goto L42
        L2c:
            java.lang.String r0 = ":"
            r1 = 6
            int r0 = kotlin.text.StringsKt.M(r8, r0, r3, r3, r1)
            java.lang.String r4 = "?"
            int r8 = kotlin.text.StringsKt.M(r8, r4, r3, r3, r1)
            r1 = 3
            if (r0 <= r1) goto L2a
            r1 = -1
            if (r8 == r1) goto L41
            if (r0 >= r8) goto L2a
        L41:
            r8 = r2
        L42:
            java.util.Iterator r0 = r7.keys()
        L46:
            boolean r1 = r0.hasNext()
            if (r1 == 0) goto L71
            java.lang.Object r1 = r0.next()
            java.lang.String r1 = (java.lang.String) r1
            java.lang.Object r4 = r7.opt(r1)
            if (r8 == 0) goto L62
            java.lang.String r5 = "image"
            boolean r5 = kotlin.text.D.l(r1, r5, r2)
            if (r5 == 0) goto L62
            r5 = r2
            goto L63
        L62:
            r5 = r3
        L63:
            java.lang.String r6 = "key"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r6)
            java.lang.String r6 = "value"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, r6)
            T(r1, r4, r9, r5)
            goto L46
        L71:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.utils.studiableMetadata.b.S(org.json.JSONObject, java.lang.String, com.facebook.s):void");
    }

    public static void T(String str, Object obj, s sVar, boolean z) {
        Class<?> cls = obj.getClass();
        if (JSONObject.class.isAssignableFrom(cls)) {
            JSONObject jSONObject = (JSONObject) obj;
            if (z) {
                Iterator<String> itKeys = jSONObject.keys();
                while (itKeys.hasNext()) {
                    String next = itKeys.next();
                    String strS = d0.s(new Object[]{str, next}, 2, "%s[%s]", "format(format, *args)");
                    Object objOpt = jSONObject.opt(next);
                    Intrinsics.checkNotNullExpressionValue(objOpt, "jsonObject.opt(propertyName)");
                    T(strS, objOpt, sVar, z);
                }
                return;
            }
            if (jSONObject.has("id")) {
                String strOptString = jSONObject.optString("id");
                Intrinsics.checkNotNullExpressionValue(strOptString, "jsonObject.optString(\"id\")");
                T(str, strOptString, sVar, z);
                return;
            } else if (jSONObject.has(DTBMetricsConfiguration.APSMETRICS_URL)) {
                String strOptString2 = jSONObject.optString(DTBMetricsConfiguration.APSMETRICS_URL);
                Intrinsics.checkNotNullExpressionValue(strOptString2, "jsonObject.optString(\"url\")");
                T(str, strOptString2, sVar, z);
                return;
            } else {
                if (jSONObject.has("fbsdk:create_object")) {
                    String string = jSONObject.toString();
                    Intrinsics.checkNotNullExpressionValue(string, "jsonObject.toString()");
                    T(str, string, sVar, z);
                    return;
                }
                return;
            }
        }
        if (JSONArray.class.isAssignableFrom(cls)) {
            JSONArray jSONArray = (JSONArray) obj;
            int length = jSONArray.length();
            for (int i = 0; i < length; i++) {
                String str2 = String.format(Locale.ROOT, "%s[%d]", Arrays.copyOf(new Object[]{str, Integer.valueOf(i)}, 2));
                Intrinsics.checkNotNullExpressionValue(str2, "format(locale, format, *args)");
                Object objOpt2 = jSONArray.opt(i);
                Intrinsics.checkNotNullExpressionValue(objOpt2, "jsonArray.opt(i)");
                T(str2, objOpt2, sVar, z);
            }
            return;
        }
        if (String.class.isAssignableFrom(cls) || Number.class.isAssignableFrom(cls) || Boolean.class.isAssignableFrom(cls)) {
            sVar.a(str, obj.toString());
            return;
        }
        if (!Date.class.isAssignableFrom(cls)) {
            String str3 = t.j;
            o oVar = o.a;
        } else {
            String str4 = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ", Locale.US).format((Date) obj);
            Intrinsics.checkNotNullExpressionValue(str4, "iso8601DateFormat.format(date)");
            sVar.a(str, str4);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v0 */
    /* JADX WARN: Type inference failed for: r2v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r2v5 */
    public static void U(v requests, A a, int i, URL url, FilterOutputStream outputStream, boolean z) throws JSONException {
        String strB;
        ?? r2 = 1;
        Intrinsics.checkNotNullParameter(outputStream, "outputStream");
        o1 o1Var = new o1();
        o1Var.c = outputStream;
        o1Var.d = a;
        o1Var.a = true;
        o1Var.b = z;
        if (i == 1) {
            t tVar = (t) requests.c.get(0);
            HashMap map = new HashMap();
            for (String key : tVar.d.keySet()) {
                Object obj = tVar.d.get(key);
                if (M(obj)) {
                    Intrinsics.checkNotNullExpressionValue(key, "key");
                    map.put(key, new p(tVar, obj));
                }
            }
            Intrinsics.checkNotNullParameter("  Parameters:\n", "string");
            a.c();
            Bundle bundle = tVar.d;
            for (String key2 : bundle.keySet()) {
                Object obj2 = bundle.get(key2);
                if (N(obj2)) {
                    Intrinsics.checkNotNullExpressionValue(key2, "key");
                    o1Var.l(key2, obj2, tVar);
                }
            }
            Intrinsics.checkNotNullParameter("  Attachments:\n", "string");
            a.c();
            X(map, o1Var);
            JSONObject jSONObject = tVar.c;
            if (jSONObject != null) {
                String path = url.getPath();
                Intrinsics.checkNotNullExpressionValue(path, "url.path");
                S(jSONObject, path, o1Var);
                return;
            }
            return;
        }
        requests.getClass();
        Iterator<E> it2 = requests.iterator();
        while (true) {
            if (it2.hasNext()) {
                AccessToken accessToken = ((t) it2.next()).a;
                if (accessToken != null) {
                    strB = accessToken.h;
                    break;
                }
            } else {
                String str = t.j;
                strB = o.b();
                break;
            }
        }
        if (strB.length() == 0) {
            throw new FacebookException("App ID was not specified at the request or Settings.");
        }
        o1Var.a("batch_app_id", strB);
        HashMap map2 = new HashMap();
        JSONArray requestJsonArray = new JSONArray();
        Iterator it3 = requests.iterator();
        while (it3.hasNext()) {
            t tVar2 = (t) it3.next();
            tVar2.getClass();
            JSONObject jSONObject2 = new JSONObject();
            String str2 = String.format("https://graph.%s", Arrays.copyOf(new Object[]{o.e()}, (int) r2));
            Intrinsics.checkNotNullExpressionValue(str2, "format(format, *args)");
            String strH = tVar2.h(str2);
            tVar2.a();
            Uri uri = Uri.parse(tVar2.b(strH, r2));
            String strS = d0.s(new Object[]{uri.getPath(), uri.getQuery()}, 2, "%s?%s", "format(format, *args)");
            jSONObject2.put("relative_url", strS);
            jSONObject2.put("method", tVar2.h);
            AccessToken accessToken2 = tVar2.a;
            if (accessToken2 != null) {
                A.c.y(accessToken2.e);
            }
            ArrayList arrayList = new ArrayList();
            Iterator<String> it4 = tVar2.d.keySet().iterator();
            while (true) {
                boolean zHasNext = it4.hasNext();
                String str3 = t.j;
                if (!zHasNext) {
                    break;
                }
                Object obj3 = tVar2.d.get(it4.next());
                if (M(obj3)) {
                    String str4 = String.format(Locale.ROOT, "%s%d", Arrays.copyOf(new Object[]{"file", Integer.valueOf(map2.size())}, 2));
                    Intrinsics.checkNotNullExpressionValue(str4, "format(locale, format, *args)");
                    arrayList.add(str4);
                    map2.put(str4, new p(tVar2, obj3));
                    it3 = it3;
                }
            }
            Iterator it5 = it3;
            if (!arrayList.isEmpty()) {
                jSONObject2.put("attached_files", TextUtils.join(",", arrayList));
            }
            JSONObject jSONObject3 = tVar2.c;
            if (jSONObject3 != null) {
                ArrayList arrayList2 = new ArrayList();
                S(jSONObject3, strS, new m(arrayList2));
                jSONObject2.put("body", TextUtils.join("&", arrayList2));
            }
            requestJsonArray.put(jSONObject2);
            it3 = it5;
            r2 = 1;
        }
        Intrinsics.checkNotNullParameter("batch", "key");
        Intrinsics.checkNotNullParameter(requestJsonArray, "requestJsonArray");
        Intrinsics.checkNotNullParameter(requests, "requests");
        String string = requestJsonArray.toString();
        Intrinsics.checkNotNullExpressionValue(string, "requestJsonArray.toString()");
        o1Var.a("batch", string);
        Intrinsics.checkNotNullParameter("  Attachments:\n", "string");
        a.c();
        X(map2, o1Var);
    }

    public static byte[][] V(byte[][] bArr) {
        byte[][] bArr2 = (byte[][]) Array.newInstance((Class<?>) Byte.TYPE, bArr[0].length, bArr.length);
        for (int i = 0; i < bArr.length; i++) {
            int length = (bArr.length - i) - 1;
            for (int i2 = 0; i2 < bArr[0].length; i2++) {
                bArr2[i2][length] = bArr[i][i2];
            }
        }
        return bArr2;
    }

    public static void W(v requests, ArrayList responses) {
        Intrinsics.checkNotNullParameter(requests, "requests");
        Intrinsics.checkNotNullParameter(responses, "responses");
        int size = requests.c.size();
        ArrayList arrayList = new ArrayList();
        for (int i = 0; i < size; i++) {
            t tVar = (t) requests.c.get(i);
            if (tVar.g != null) {
                arrayList.add(new Pair(tVar.g, responses.get(i)));
            }
        }
        if (arrayList.size() > 0) {
            androidx.credentials.playservices.controllers.c cVar = new androidx.credentials.playservices.controllers.c(14, arrayList, requests);
            Handler handler = requests.a;
            if (handler != null) {
                handler.post(cVar);
            } else {
                cVar.run();
            }
        }
    }

    public static void X(HashMap map, o1 o1Var) {
        for (Map.Entry entry : map.entrySet()) {
            String str = t.j;
            if (M(((p) entry.getValue()).b)) {
                o1Var.l((String) entry.getKey(), ((p) entry.getValue()).b, ((p) entry.getValue()).a);
            }
        }
    }

    public static void Y(v requests, HttpURLConnection connection) throws Throwable {
        boolean z;
        Throwable th;
        Intrinsics.checkNotNullParameter(requests, "requests");
        Intrinsics.checkNotNullParameter(connection, "connection");
        A a = new A();
        int size = requests.c.size();
        Iterator<E> it2 = requests.iterator();
        loop0: while (true) {
            if (!it2.hasNext()) {
                z = true;
                break;
            }
            t tVar = (t) it2.next();
            Iterator<String> it3 = tVar.d.keySet().iterator();
            while (it3.hasNext()) {
                if (M(tVar.d.get(it3.next()))) {
                    z = false;
                    break loop0;
                }
            }
        }
        FilterOutputStream filterOutputStream = null;
        x xVar = size == 1 ? ((t) requests.c.get(0)).h : null;
        x xVar2 = x.b;
        if (xVar == null) {
            xVar = xVar2;
        }
        connection.setRequestMethod(xVar.name());
        if (z) {
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setRequestProperty("Content-Encoding", "gzip");
        } else {
            connection.setRequestProperty("Content-Type", d0.s(new Object[]{t.j}, 1, "multipart/form-data; boundary=%s", "format(format, *args)"));
        }
        URL url = connection.getURL();
        Intrinsics.checkNotNullParameter("Request:\n", "string");
        a.c();
        a.a(requests.b, "Id");
        Intrinsics.checkNotNullExpressionValue(url, "url");
        a.a(url, "URL");
        String requestMethod = connection.getRequestMethod();
        Intrinsics.checkNotNullExpressionValue(requestMethod, "connection.requestMethod");
        a.a(requestMethod, "Method");
        String requestProperty = connection.getRequestProperty("User-Agent");
        Intrinsics.checkNotNullExpressionValue(requestProperty, "connection.getRequestProperty(\"User-Agent\")");
        a.a(requestProperty, "User-Agent");
        String requestProperty2 = connection.getRequestProperty("Content-Type");
        Intrinsics.checkNotNullExpressionValue(requestProperty2, "connection.getRequestProperty(\"Content-Type\")");
        a.a(requestProperty2, "Content-Type");
        connection.setConnectTimeout(0);
        connection.setReadTimeout(0);
        if (xVar != xVar2) {
            a.b();
            return;
        }
        connection.setDoOutput(true);
        try {
            FilterOutputStream bufferedOutputStream = new BufferedOutputStream(connection.getOutputStream());
            if (z) {
                try {
                    bufferedOutputStream = new GZIPOutputStream(bufferedOutputStream);
                } catch (Throwable th2) {
                    th = th2;
                    filterOutputStream = bufferedOutputStream;
                    if (filterOutputStream == null) {
                        throw th;
                    }
                    filterOutputStream.close();
                    throw th;
                }
            }
            Iterator it4 = requests.d.iterator();
            while (it4.hasNext()) {
            }
            Iterator<E> it5 = requests.iterator();
            while (it5.hasNext()) {
                q qVar = ((t) it5.next()).g;
            }
            U(requests, a, size, url, bufferedOutputStream, z);
            bufferedOutputStream.close();
            a.b();
        } catch (Throwable th3) {
            th = th3;
        }
    }

    public static HttpURLConnection Z(v requests) throws Throwable {
        URL url;
        Intrinsics.checkNotNullParameter(requests, "requests");
        Intrinsics.checkNotNullParameter(requests, "requests");
        Iterator<E> it2 = requests.iterator();
        while (it2.hasNext()) {
            t tVar = (t) it2.next();
            if (x.a == tVar.h && J.D(tVar.d.getString("fields"))) {
                com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
                y yVar = y.e;
                StringBuilder sb = new StringBuilder("GET requests for /");
                String str = tVar.b;
                if (str == null) {
                    str = "";
                }
                sb.append(str);
                sb.append(" should contain an explicit \"fields\" parameter.");
                com.google.mlkit.common.sdkinternal.model.a.x(yVar, "Request", sb.toString());
            }
        }
        try {
            if (requests.c.size() == 1) {
                url = new URL(((t) requests.c.get(0)).g());
            } else {
                String str2 = String.format("https://graph.%s", Arrays.copyOf(new Object[]{o.e()}, 1));
                Intrinsics.checkNotNullExpressionValue(str2, "format(format, *args)");
                url = new URL(str2);
            }
            HttpURLConnection httpURLConnectionG = null;
            try {
                httpURLConnectionG = G(url);
                Y(requests, httpURLConnectionG);
                return httpURLConnectionG;
            } catch (IOException e) {
                J.k(httpURLConnectionG);
                throw new FacebookException("could not construct request body", e);
            } catch (JSONException e2) {
                J.k(httpURLConnectionG);
                throw new FacebookException("could not construct request body", e2);
            }
        } catch (MalformedURLException e3) {
            throw new FacebookException("could not construct URL for request", e3);
        }
    }

    public static final void a0(Context context, AdOverlayInfoParcel adOverlayInfoParcel, boolean z, Hk hk) {
        if (adOverlayInfoParcel.k == 4 && adOverlayInfoParcel.c == null) {
            InterfaceC1582a interfaceC1582a = adOverlayInfoParcel.b;
            if (interfaceC1582a != null) {
                interfaceC1582a.onAdClicked();
            }
            InterfaceC2447oi interfaceC2447oi = adOverlayInfoParcel.u;
            if (interfaceC2447oi != null) {
                interfaceC2447oi.c0();
            }
            Activity activityZzi = adOverlayInfoParcel.d.zzi();
            zzc zzcVar = adOverlayInfoParcel.a;
            Context context2 = (zzcVar == null || !zzcVar.j || activityZzi == null) ? context : activityZzi;
            com.quizlet.shared.usecase.srs.a aVar = j.C.a;
            com.quizlet.shared.usecase.srs.a.z(context2, zzcVar, adOverlayInfoParcel.i, zzcVar != null ? zzcVar.i : null, hk, adOverlayInfoParcel.q);
            return;
        }
        Intent intent = new Intent();
        intent.setClassName(context, "com.google.android.gms.ads.AdActivity");
        intent.putExtra("com.google.android.gms.ads.internal.overlay.useClientJar", adOverlayInfoParcel.m.d);
        intent.putExtra("shouldCallOnOverlayOpened", z);
        Bundle bundle = new Bundle(1);
        bundle.putParcelable("com.google.android.gms.ads.inernal.overlay.AdOverlayInfo", adOverlayInfoParcel);
        intent.putExtra("com.google.android.gms.ads.inernal.overlay.AdOverlayInfo", bundle);
        if (!(context instanceof Activity)) {
            intent.addFlags(268435456);
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Zc)).booleanValue()) {
            F f = j.C.c;
            F.s(context, intent, hk, adOverlayInfoParcel.q);
        } else {
            F f2 = j.C.c;
            F.q(context, intent);
        }
    }

    public static final CharSequence b0(Object obj) {
        Objects.requireNonNull(obj);
        return obj instanceof CharSequence ? (CharSequence) obj : obj.toString();
    }

    public static int i(Context context, boolean z) {
        if (Build.VERSION.SDK_INT < 30) {
            DisplayMetrics displayMetrics = new DisplayMetrics();
            Objects.requireNonNull(context);
            ((Activity) context).getWindowManager().getDefaultDisplay().getMetrics(displayMetrics);
            return z ? displayMetrics.heightPixels : displayMetrics.widthPixels;
        }
        Objects.requireNonNull(context);
        WindowMetrics currentWindowMetrics = ((Activity) context).getWindowManager().getCurrentWindowMetrics();
        Insets insetsIgnoringVisibility = currentWindowMetrics.getWindowInsets().getInsetsIgnoringVisibility(WindowInsets.Type.navigationBars() | WindowInsets.Type.displayCutout());
        int i = insetsIgnoringVisibility.left + insetsIgnoringVisibility.right;
        int i2 = insetsIgnoringVisibility.bottom + insetsIgnoringVisibility.top;
        Rect bounds = currentWindowMetrics.getBounds();
        Size size = new Size(bounds.width() - i, bounds.height() - i2);
        return z ? size.getHeight() : size.getWidth();
    }

    public static View j(Context context, LayoutInflater layoutInflater, ViewGroup viewGroup, int i) {
        return com.onetrust.otpublishers.headless.Internal.a.o(context) ? layoutInflater.cloneInContext(new androidx.appcompat.view.d(context, R.style.Theme_AppCompat_Light_NoActionBar)).inflate(i, viewGroup, false) : layoutInflater.inflate(i, viewGroup, false);
    }

    public static String k(long j, JSONObject jSONObject) {
        String string;
        StringBuilder sb;
        String strOptString;
        if (j <= 0) {
            return "0 " + jSONObject.optString("PCenterVendorListLifespanDays");
        }
        int i = (int) (j / 2629746);
        int i2 = ((int) (j % 2629746)) / 86400;
        String str = "";
        if (i != 0) {
            if (i != 1) {
                sb = new StringBuilder();
                sb.append(i);
                sb.append(" ");
                strOptString = jSONObject.optString("PCenterVendorListLifespanMonths");
            } else {
                sb = new StringBuilder();
                sb.append(i);
                sb.append(" ");
                strOptString = jSONObject.optString("PCenterVendorListLifespanMonth");
            }
            sb.append(strOptString);
            string = sb.toString();
        } else {
            string = "";
        }
        if (i2 == 0) {
            boolean z = i == 0;
            String str2 = "0 " + jSONObject.optString("PCenterVendorListLifespanDays");
            if (z) {
                str = str2;
            }
        } else if (i2 != 1) {
            if (30 != i2) {
                str = i2 + " " + jSONObject.optString("PCenterVendorListLifespanDays");
            }
            if (30 == i2) {
                int i3 = i + 1;
                string = i3 + " " + (i3 == 1 ? jSONObject.optString("PCenterVendorListLifespanMonth") : jSONObject.optString("PCenterVendorListLifespanMonths"));
            }
        } else {
            str = i2 + " " + jSONObject.optString("PCenterVendorListLifespanDay");
        }
        return android.support.v4.media.session.a.l(string, " ", str);
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x004a  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0098  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00a4  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String m(android.content.Context r4, org.json.JSONObject r5, org.json.JSONObject r6, java.lang.String r7, boolean r8) throws org.json.JSONException {
        /*
            com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r0 = new com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK
            r0.<init>(r4)
            org.json.JSONObject r4 = r0.getPreferenceCenterData()
            boolean r7 = com.onetrust.otpublishers.headless.Internal.a.l(r7)
            java.lang.String r0 = ""
            if (r7 == 0) goto Lbf
            java.lang.String r7 = "IAB"
            java.lang.String r1 = "Type"
            if (r8 == 0) goto L22
            java.lang.String r8 = r6.optString(r1)
            boolean r8 = r8.contains(r7)
            if (r8 == 0) goto L22
            goto L48
        L22:
            org.json.JSONArray r8 = new org.json.JSONArray
            r8.<init>()
            java.lang.String r2 = "SubGroups"
            boolean r3 = r6.has(r2)
            if (r3 == 0) goto L33
            org.json.JSONArray r8 = r6.getJSONArray(r2)
        L33:
            r2 = 0
        L34:
            int r3 = r8.length()
            if (r2 >= r3) goto Lbf
            org.json.JSONObject r3 = r8.getJSONObject(r2)
            java.lang.String r3 = r3.optString(r1)
            boolean r3 = r3.contains(r7)
            if (r3 == 0) goto Lbb
        L48:
            if (r4 == 0) goto Lbf
            java.lang.String r7 = "CustomGroupId"
            java.lang.String r6 = r6.optString(r7)
            java.lang.String r7 = "IFEV2"
            boolean r7 = r6.startsWith(r7)
            if (r7 != 0) goto L8f
            java.lang.String r7 = "IFE2V2"
            boolean r7 = r6.startsWith(r7)
            if (r7 == 0) goto L61
            goto L8f
        L61:
            java.lang.String r7 = "ISFV2"
            boolean r7 = r6.startsWith(r7)
            if (r7 != 0) goto L8c
            java.lang.String r7 = "ISF2V2"
            boolean r7 = r6.startsWith(r7)
            if (r7 == 0) goto L72
            goto L8c
        L72:
            java.lang.String r7 = "ISPV2"
            boolean r7 = r6.startsWith(r7)
            if (r7 != 0) goto L85
            java.lang.String r7 = "ISP2V2"
            boolean r7 = r6.startsWith(r7)
            if (r7 == 0) goto L83
            goto L85
        L83:
            r7 = r0
            goto L92
        L85:
            java.lang.String r7 = "PCVendorsCountSpcPurposeText"
        L87:
            java.lang.String r7 = r4.optString(r7)
            goto L92
        L8c:
            java.lang.String r7 = "PCVendorsCountSpcFeatureText"
            goto L87
        L8f:
            java.lang.String r7 = "PCVendorsCountFeatureText"
            goto L87
        L92:
            boolean r8 = com.onetrust.otpublishers.headless.Internal.a.j(r7)
            if (r8 == 0) goto L9e
            java.lang.String r7 = "PCVendorsCountText"
            java.lang.String r7 = r4.optString(r7)
        L9e:
            boolean r4 = com.onetrust.otpublishers.headless.Internal.a.j(r7)
            if (r4 != 0) goto Lbf
            java.lang.String r4 = o(r6, r5)
            boolean r5 = com.onetrust.otpublishers.headless.Internal.a.j(r4)
            if (r5 != 0) goto Lbf
            int r5 = java.lang.Integer.parseInt(r4)
            if (r5 <= 0) goto Lbf
            java.lang.String r5 = "[VENDOR_NUMBER]"
            java.lang.String r4 = r7.replace(r5, r4)
            return r4
        Lbb:
            int r2 = r2 + 1
            goto L34
        Lbf:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.utils.studiableMetadata.b.m(android.content.Context, org.json.JSONObject, org.json.JSONObject, java.lang.String, boolean):java.lang.String");
    }

    public static String n(String str) {
        int i;
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return "";
        }
        if ("center".equalsIgnoreCase(str)) {
            i = 4;
        } else if ("left".equalsIgnoreCase(str)) {
            i = 2;
        } else {
            if (!"right".equalsIgnoreCase(str)) {
                return "";
            }
            i = 3;
        }
        return String.valueOf(i);
    }

    public static String o(String str, JSONObject jSONObject) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str) || !jSONObject.has(str)) {
            return "";
        }
        try {
            return jSONObject.getString(str);
        } catch (JSONException e) {
            Z.p("Error on getting vendor count for category : ", e, "UIUtils", 6);
            return "";
        }
    }

    public static JSONArray p(JSONArray jSONArray) throws JSONException {
        JSONArray jSONArray2 = new JSONArray();
        for (int i = 0; i < jSONArray.length(); i++) {
            try {
                JSONObject jSONObject = new JSONObject();
                JSONObject jSONObject2 = jSONArray.getJSONObject(i);
                OTLogger.c("UIUtils", 3, "Individual Purpose List: " + jSONObject2.getString("Type") + "  " + jSONObject2.getString("GroupName"));
                if (!jSONObject2.getString("Type").contains("IAB2_STACK") && !jSONObject2.getString("Type").contains("IAB2V2_STACK") && !jSONObject2.getString("Type").contains("COOKIE") && !jSONObject2.getString("Type").contains("BRANCH")) {
                    jSONObject.put("CustomGroupId", jSONObject2.optString("CustomGroupId", ""));
                    jSONObject.put("GroupName", jSONObject2.optString("GroupName", ""));
                    jSONObject.put("Type", jSONObject2.optString("Type", ""));
                    jSONArray2.put(jSONObject);
                }
                A(jSONArray2, jSONObject2);
            } catch (JSONException e) {
                Z.p("getPurposeList: ", e, "UIUtils", 6);
            }
        }
        return jSONArray2;
    }

    public static void q(Context context, Button button, n nVar, String str, String str2) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            OTLogger.c("UIUtils", 3, "Button set background color called with empty buttonBackGroundColor.");
            return;
        }
        if (com.onetrust.otpublishers.headless.Internal.a.o(context)) {
            button.setBackgroundColor(Color.parseColor(str));
            return;
        }
        if (nVar != null) {
            String str3 = (String) nVar.h;
            String str4 = (String) nVar.i;
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str3) || !com.onetrust.otpublishers.headless.Internal.a.j(str4)) {
                String str5 = (String) nVar.h;
                if (com.onetrust.otpublishers.headless.Internal.a.j(str5)) {
                    str5 = "4";
                }
                if (com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
                    str2 = str;
                }
                GradientDrawable gradientDrawable = new GradientDrawable();
                gradientDrawable.setShape(0);
                gradientDrawable.setStroke(Integer.parseInt(str5), Color.parseColor(str2));
                gradientDrawable.setColor(Color.parseColor(str));
                if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.i)) {
                    gradientDrawable.setCornerRadius(TypedValue.applyDimension(1, Integer.parseInt((String) nVar.i), context.getResources().getDisplayMetrics()));
                }
                button.setBackground(gradientDrawable);
                return;
            }
        }
        v(button, str, str2);
    }

    public static void r(Context context, TextView textView, String str) {
        if (str == null || com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            OTLogger.c("UIUtils", 3, "renderHtmlText called with 'null' text content.");
            return;
        }
        if (!Pattern.compile(".*\\<[^>]+>.*", 32).matcher(str).matches()) {
            textView.setText(str);
            return;
        }
        OTLogger.c("UIUtils", 3, "Rendering html content");
        Spanned spannedFromHtml = Html.fromHtml(str, 0);
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(spannedFromHtml);
        for (URLSpan uRLSpan : (URLSpan[]) spannableStringBuilder.getSpans(0, spannedFromHtml.length(), URLSpan.class)) {
            spannableStringBuilder.setSpan(new com.onetrust.otpublishers.headless.UI.Helper.d(context, uRLSpan, 0), spannableStringBuilder.getSpanStart(uRLSpan), spannableStringBuilder.getSpanEnd(uRLSpan), spannableStringBuilder.getSpanFlags(uRLSpan));
            spannableStringBuilder.removeSpan(uRLSpan);
        }
        textView.setText(spannableStringBuilder);
        textView.setMovementMethod(LinkMovementMethod.getInstance());
    }

    public static void s(Context context, SwitchCompat switchCompat, String str, String str2) {
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            switchCompat.getTrackDrawable().setTint(context.getColor(R.color.light_greyOT));
        } else {
            switchCompat.getTrackDrawable().setTint(Color.parseColor(str));
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
            switchCompat.getThumbDrawable().setTint(context.getColor(R.color.contentTextColorOT));
        } else {
            switchCompat.getThumbDrawable().setTint(Color.parseColor(str2));
        }
    }

    public static void t(ViewGroup viewGroup, Context context) {
        if (Build.VERSION.SDK_INT < 28) {
            RelativeLayout.LayoutParams layoutParams = (RelativeLayout.LayoutParams) viewGroup.getLayoutParams();
            layoutParams.setMargins(0, 0, 0, 60);
            viewGroup.setLayoutParams(layoutParams);
            return;
        }
        Objects.requireNonNull(context);
        View decorView = ((Activity) context).getWindow().getDecorView();
        if ((decorView.getRootWindowInsets() != null ? decorView.getRootWindowInsets().getDisplayCutout() : null) != null) {
            OTLogger.c("UIUtils", 5, "Device is notch enabled");
            RelativeLayout.LayoutParams layoutParams2 = (RelativeLayout.LayoutParams) viewGroup.getLayoutParams();
            layoutParams2.setMargins(0, 0, 0, 50);
            viewGroup.setLayoutParams(layoutParams2);
            return;
        }
        OTLogger.c("UIUtils", 5, "Device is not notch enabled");
        RelativeLayout.LayoutParams layoutParams3 = (RelativeLayout.LayoutParams) viewGroup.getLayoutParams();
        layoutParams3.setMargins(0, 0, 0, 70);
        viewGroup.setLayoutParams(layoutParams3);
    }

    public static void u(Button button, k kVar, OTConfiguration oTConfiguration) {
        Typeface typeface;
        Typeface otTypeFaceMap;
        String str = (String) kVar.e;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str) && oTConfiguration != null && (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str)) != null) {
            button.setTypeface(otTypeFaceMap);
            return;
        }
        int style = kVar.b;
        if (style == -1 && (typeface = button.getTypeface()) != null) {
            style = typeface.getStyle();
        }
        button.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.c) ? Typeface.create((String) kVar.c, style) : Typeface.create(button.getTypeface(), style));
    }

    public static void v(Button button, String str, String str2) {
        if (button.getId() != R.id.cookies_setting_button) {
            button.setBackgroundColor(Color.parseColor(str));
            return;
        }
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setShape(0);
        gradientDrawable.setStroke(Integer.parseInt("3"), Color.parseColor(str2));
        gradientDrawable.setColor(Color.parseColor(str));
        gradientDrawable.setCornerRadius(Float.parseFloat("0"));
        button.setBackground(gradientDrawable);
    }

    public static void w(TextView textView, k kVar, OTConfiguration oTConfiguration) {
        Typeface otTypeFaceMap;
        String str = (String) kVar.e;
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str) && oTConfiguration != null && (otTypeFaceMap = oTConfiguration.getOtTypeFaceMap(str)) != null) {
            textView.setTypeface(otTypeFaceMap);
        } else {
            int iA = k.a(textView, kVar.b);
            textView.setTypeface(!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.c) ? Typeface.create((String) kVar.c, iA) : Typeface.create(textView.getTypeface(), iA));
        }
    }

    public static void x(TextView textView, String str) throws NumberFormatException {
        if (P.k(textView.getContext())) {
            textView.setTextAlignment(5);
            return;
        }
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return;
        }
        int i = Integer.parseInt(str);
        int i2 = 8388613;
        int i3 = 8388611;
        if (textView.getContext().getResources().getConfiguration().getLayoutDirection() != 1) {
            i3 = 8388613;
            i2 = 8388611;
        }
        if (i == 2) {
            textView.setGravity(3);
            return;
        }
        if (i == 3) {
            textView.setGravity(5);
            return;
        }
        if (i == 4) {
            textView.setGravity(1);
        } else if (i == 5) {
            textView.setGravity(i2);
        } else {
            if (i != 6) {
                return;
            }
            textView.setGravity(i3);
        }
    }

    public static void y(androidx.compose.foundation.lazy.grid.m mVar, com.onetrust.otpublishers.headless.Internal.Event.a aVar) {
        if (aVar != null) {
            aVar.a(mVar);
        } else {
            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
        }
    }

    public static void z(I i, h hVar) {
        if (i != null && hVar == null) {
            OTLogger.c("UIUtils", 3, "setupFullHeight: null instance found, recreating bottomSheetDialog");
            SharedPreferences sharedPreferences = i.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOT_SDK_APP_CONFIGURATION", 0);
            String str = OTThemeConstants.NO_SDK_THEME_OVERRIDE;
            String string = sharedPreferences.getString("OT_UX_SDK_THEME", OTThemeConstants.NO_SDK_THEME_OVERRIDE);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                str = string;
            }
            hVar = str.equals(OTThemeConstants.OT_SDK_UI_THEME) ? new h(i, R.style.OTSDKTheme) : new h(i);
        }
        FrameLayout frameLayout = (FrameLayout) hVar.findViewById(R.id.design_bottom_sheet);
        if (frameLayout != null) {
            BottomSheetBehavior bottomSheetBehaviorC = BottomSheetBehavior.C(frameLayout);
            ViewGroup.LayoutParams layoutParams = frameLayout.getLayoutParams();
            int i2 = i(i, true);
            if (layoutParams != null) {
                layoutParams.height = i2;
            }
            frameLayout.setLayoutParams(layoutParams);
            bottomSheetBehaviorC.J(3);
            bottomSheetBehaviorC.I(i(i, true));
        }
    }

    public io.reactivex.rxjava3.core.p L(androidx.work.impl.model.c userProps) {
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        return com.google.android.gms.dynamite.d.f(userProps.t(), userProps.s());
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public com.perimeterx.mobile_sdk.doctor_app.state.a a() {
        return null;
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public com.perimeterx.mobile_sdk.doctor_app.state.a b() {
        return null;
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public Fragment c() {
        return new com.perimeterx.mobile_sdk.doctor_app.ui.t();
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public ArrayList d() {
        return new ArrayList();
    }

    @Override // androidx.compose.ui.text.font.z
    public Typeface e(u uVar, int i) {
        return F(null, uVar, i);
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        com.google.mlkit.common.sdkinternal.a aVar = new com.google.mlkit.common.sdkinternal.a();
        androidx.emoji2.text.n nVar = new androidx.emoji2.text.n(2);
        ReferenceQueue referenceQueue = aVar.a;
        Set set = aVar.b;
        set.add(new com.google.mlkit.common.sdkinternal.j(aVar, referenceQueue, set, nVar));
        Thread thread = new Thread(new A0(referenceQueue, false, set, 10), "MlKitCleaner");
        thread.setDaemon(true);
        thread.start();
        return aVar;
    }

    @Override // com.quizlet.local.ormlite.util.c
    public ArrayList g(List list) {
        return AbstractC3771z.c(this, list);
    }

    @Override // com.quizlet.local.ormlite.util.c
    public /* bridge */ /* synthetic */ Object h(Object obj) {
        return O((DBUser) obj);
    }

    /* JADX WARN: Removed duplicated region for block: B:176:0x032c  */
    /* JADX WARN: Removed duplicated region for block: B:188:0x0364  */
    /* JADX WARN: Removed duplicated region for block: B:228:0x046e A[LOOP:12: B:227:0x046c->B:228:0x046e, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:231:0x0489  */
    /* JADX WARN: Removed duplicated region for block: B:232:0x0493  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0079  */
    @Override // com.google.zxing.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.zxing.common.b l(java.lang.String r30, int r31, int r32, int r33, java.util.EnumMap r34) throws com.google.zxing.WriterException {
        /*
            Method dump skipped, instructions count: 1355
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.utils.studiableMetadata.b.l(java.lang.String, int, int, int, java.util.EnumMap):com.google.zxing.common.b");
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 11:
                List list = AbstractC3893t.a;
                W3.b.get();
                Boolean bool = (Boolean) Y3.g.b();
                bool.getClass();
                return bool;
            case 12:
                List list2 = AbstractC3893t.a;
                E3.b.get();
                Boolean bool2 = (Boolean) G3.d.b();
                bool2.getClass();
                return bool2;
            case 13:
                List list3 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.l0.b()).longValue());
            case 14:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.M.b()).longValue());
            case 15:
                List list5 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.d0.b();
                l.getClass();
                return l;
            case 16:
                List list6 = AbstractC3893t.a;
                B3.b.get();
                Long l2 = (Long) D3.b.b();
                l2.getClass();
                return l2;
            default:
                List list7 = AbstractC3893t.a;
                O2.b.get();
                Long l3 = (Long) Q2.i.b();
                l3.getClass();
                return l3;
        }
    }

    public b(int[] iArr, ValueAnimator valueAnimator) {
        this.a = 18;
    }

    public static int d(Context context, OTConfiguration oTConfiguration) {
        return (oTConfiguration == null || com.onetrust.otpublishers.headless.Internal.a.j(oTConfiguration.getDarkModeThemeValue())) ? 32 == (context.getResources().getConfiguration().uiMode & 48) ? 11 : 22 : AbstractC3605e0.a(oTConfiguration.getDarkModeThemeValue()) ? 11 : 22;
    }

    @Override // com.bumptech.glide.manager.g
    public void a(i iVar) {
        iVar.onStart();
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x001b  */
    @Override // androidx.compose.ui.text.font.z
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public android.graphics.Typeface b(androidx.compose.ui.text.font.w r5, androidx.compose.ui.text.font.u r6, int r7) {
        /*
            r4 = this;
            r5.getClass()
            int r5 = r6.a
            int r5 = r5 / 100
            java.lang.String r0 = "sans-serif"
            r1 = 2
            if (r5 < 0) goto L11
            if (r5 >= r1) goto L11
            java.lang.String r5 = "sans-serif-thin"
            goto L33
        L11:
            r2 = 4
            if (r1 > r5) goto L19
            if (r5 >= r2) goto L19
            java.lang.String r5 = "sans-serif-light"
            goto L33
        L19:
            if (r5 != r2) goto L1d
        L1b:
            r5 = r0
            goto L33
        L1d:
            r1 = 5
            if (r5 != r1) goto L23
            java.lang.String r5 = "sans-serif-medium"
            goto L33
        L23:
            r1 = 6
            r2 = 8
            if (r1 > r5) goto L2b
            if (r5 >= r2) goto L2b
            goto L1b
        L2b:
            if (r2 > r5) goto L1b
            r1 = 11
            if (r5 >= r1) goto L1b
            java.lang.String r5 = "sans-serif-black"
        L33:
            int r1 = r5.length()
            r2 = 0
            if (r1 != 0) goto L3b
            goto L5a
        L3b:
            android.graphics.Typeface r5 = F(r5, r6, r7)
            android.graphics.Typeface r1 = android.graphics.Typeface.DEFAULT
            int r3 = com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3249r5.c(r6, r7)
            android.graphics.Typeface r1 = android.graphics.Typeface.create(r1, r3)
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r5, r1)
            if (r1 != 0) goto L5a
            android.graphics.Typeface r1 = F(r2, r6, r7)
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r5, r1)
            if (r1 != 0) goto L5a
            r2 = r5
        L5a:
            if (r2 != 0) goto L61
            android.graphics.Typeface r5 = F(r0, r6, r7)
            return r5
        L61:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.utils.studiableMetadata.b.b(androidx.compose.ui.text.font.w, androidx.compose.ui.text.font.u, int):android.graphics.Typeface");
    }

    @Override // com.bumptech.glide.manager.g
    public void c(i iVar) {
    }
}
