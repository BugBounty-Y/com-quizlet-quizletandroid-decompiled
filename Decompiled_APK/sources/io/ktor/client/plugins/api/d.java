package io.ktor.client.plugins.api;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.SystemClock;
import androidx.camera.core.C0155g;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.core.processing.j;
import androidx.camera.core.processing.k;
import androidx.compose.foundation.gestures.l1;
import androidx.compose.foundation.lazy.layout.C0429a;
import androidx.compose.foundation.text.input.internal.u;
import androidx.paging.D;
import androidx.paging.E;
import androidx.paging.F;
import androidx.paging.G;
import com.braze.C1510p;
import com.bumptech.glide.load.ImageHeaderParser$ImageType;
import com.bumptech.glide.load.resource.bitmap.v;
import com.google.android.gms.common.internal.MethodInvocation;
import com.google.android.gms.common.internal.TelemetryData;
import com.google.android.gms.internal.ads.C1881be;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3125d6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_barcode.T5;
import com.google.android.gms.internal.mlkit_vision_barcode.U5;
import com.google.android.gms.internal.mlkit_vision_barcode.V5;
import com.google.android.gms.internal.mlkit_vision_barcode.W5;
import com.google.android.gms.internal.mlkit_vision_barcode.X5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3567z;
import com.google.android.gms.measurement.internal.Y;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.Authentication;
import com.quizlet.api.model.DataWrapper;
import com.quizlet.api.model.ModelWrapper;
import com.quizlet.api.model.ServerProvidedError;
import com.quizlet.api.util.ApiErrorResolverWrapper;
import com.quizlet.api.util.OneOffAPIParser;
import com.quizlet.assembly.compose.buttons.Z;
import com.quizlet.data.model.C4168t1;
import com.quizlet.data.model.N1;
import com.quizlet.data.model.Question;
import com.quizlet.data.model.StudyMaterialItem$ExplanationQuestionItem;
import com.quizlet.data.model.StudyMaterialItem$FlashcardSetItem;
import com.quizlet.data.model.StudyMaterialItem$FolderItem;
import com.quizlet.data.model.StudyMaterialItem$NoteItem;
import com.quizlet.data.model.StudyMaterialItem$TextbookExerciseItem;
import com.quizlet.data.model.StudyMaterialItem$TextbookItem;
import com.quizlet.data.model.StudySetWithCreator;
import com.quizlet.data.model.User;
import com.quizlet.db.data.caches.UserInfoCacheKt;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.folders.data.z0;
import com.quizlet.features.folders.viewmodel.usecases.NoRecommendationsException;
import com.quizlet.generated.enums.O1;
import com.quizlet.login.authentication.data.l;
import com.quizlet.login.authentication.data.m;
import com.quizlet.quizletandroid.R;
import com.quizlet.remote.exceptions.NetException;
import com.quizlet.remote.service.y;
import com.quizlet.shared.httpclient.exceptions.NetworkErrorException;
import com.quizlet.ui.models.content.listitem.n;
import com.quizlet.ui.models.content.listitem.o;
import io.ktor.client.plugins.InterfaceC4874v;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.observable.C4896o;
import io.reactivex.rxjava3.internal.operators.observable.C4905y;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.L;
import kotlin.jvm.internal.Q;
import kotlin.jvm.internal.U;
import kotlin.reflect.KTypeProjection;
import kotlin.reflect.q;
import kotlin.reflect.s;
import kotlinx.coroutines.AbstractC5040y;
import okhttp3.H;
import okhttp3.InterfaceC5076e;
import okhttp3.InterfaceC5077f;
import okhttp3.J;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class d implements InterfaceC4874v, v, InterfaceC5077f {
    public static d e;
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;

    public /* synthetic */ d(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    public static final com.quizlet.login.authentication.data.i g(d dVar, String str, K response) {
        ServerProvidedError error;
        ModelWrapper modelWrapper;
        List<DBUser> users;
        dVar.getClass();
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) response.b;
        boolean z = true;
        if (apiThreeWrapper == null) {
            return new com.quizlet.login.authentication.data.d(true);
        }
        List responses = apiThreeWrapper.getResponses();
        boolean z2 = responses != null && (responses.isEmpty() ^ true);
        ApiResponse apiResponse = responses != null ? (ApiResponse) CollectionsKt.firstOrNull(responses) : null;
        if (apiResponse == null || (error = apiResponse.getError()) == null) {
            error = apiThreeWrapper.getError();
        }
        DataWrapper dataWrapper = (DataWrapper) apiThreeWrapper.getFirstData();
        Authentication authentication = dataWrapper != null ? dataWrapper.getAuthentication() : null;
        DBUser dBUser = (apiResponse == null || (modelWrapper = apiResponse.getModelWrapper()) == null || (users = modelWrapper.getUsers()) == null) ? null : (DBUser) CollectionsKt.firstOrNull(users);
        String accessToken = authentication != null ? authentication.getAccessToken() : null;
        Boolean boolValueOf = authentication != null ? Boolean.valueOf(authentication.isShouldSeeUpsell()) : null;
        if (z2 && error == null && authentication != null && dBUser != null && accessToken != null) {
            return (boolValueOf == null || !boolValueOf.booleanValue()) ? new l(accessToken, dBUser) : new m(accessToken, dBUser);
        }
        if (error != null) {
            return dVar.n(str, responses, authentication, error);
        }
        Intrinsics.checkNotNullParameter(response, "response");
        Intrinsics.checkNotNullParameter(response, "response");
        try {
            J j = response.a.g;
            Intrinsics.d(j);
            String strF = j.f();
            if (responses == null) {
                strF = "null result";
            }
            timber.log.c.a.e(new NetException(strF));
        } catch (IOException e2) {
            timber.log.c.a.e(e2);
            z = false;
        }
        return new com.quizlet.login.authentication.data.d(z);
    }

    public static String i(HashMap map, String str) {
        StringBuilder sb = new StringBuilder();
        Iterator it2 = map.entrySet().iterator();
        Map.Entry entry = (Map.Entry) it2.next();
        sb.append((String) entry.getKey());
        sb.append(SimpleComparison.EQUAL_TO_OPERATION);
        sb.append(entry.getValue() != null ? URLEncoder.encode((String) entry.getValue(), "UTF-8") : "");
        while (it2.hasNext()) {
            Map.Entry entry2 = (Map.Entry) it2.next();
            sb.append("&");
            sb.append((String) entry2.getKey());
            sb.append(SimpleComparison.EQUAL_TO_OPERATION);
            sb.append(entry2.getValue() != null ? URLEncoder.encode((String) entry2.getValue(), "UTF-8") : "");
        }
        String string = sb.toString();
        if (string.isEmpty()) {
            return str;
        }
        if (!str.contains("?")) {
            return android.support.v4.media.session.a.l(str, "?", string);
        }
        if (!str.endsWith("&")) {
            string = "&".concat(string);
        }
        return android.support.v4.media.session.a.k(str, string);
    }

    public boolean A(com.quizlet.quizletandroid.managers.audio.c payload) {
        String string;
        Intrinsics.checkNotNullParameter(payload, "payload");
        String str = payload.a;
        if (org.apache.commons.lang3.e.c(str)) {
            return false;
        }
        Context context = (Context) this.b;
        if (Intrinsics.b(context.getString(R.string.elipsis), str)) {
            return false;
        }
        Intrinsics.d(str);
        if (str.length() > 300) {
            string = context.getString(R.string.text_too_long);
            Intrinsics.d(string);
        } else if (payload.b < 0) {
            string = context.getString(R.string.audio_not_created);
            Intrinsics.d(string);
        } else {
            List list = com.quizlet.generated.sharedconfig.c.a;
            String str2 = payload.c;
            if (CollectionsKt.F(list, str2)) {
                string = context.getString(R.string.audio_not_supported, context.getString(R.string.this_term));
                Intrinsics.d(string);
            } else {
                String strD = ((com.quizlet.quizletandroid.util.f) this.c).d(str2);
                if (strD == null) {
                    strD = context.getString(payload.d);
                    Intrinsics.checkNotNullExpressionValue(strD, "getString(...)");
                }
                string = context.getString(R.string.audio_not_supported, strD);
                Intrinsics.d(string);
            }
        }
        AbstractC3125d6.d(context, string);
        return true;
    }

    public F B() {
        return new F((E) this.b, (E) this.c, (E) this.d);
    }

    public synchronized void C(int i, int i2, long j, long j2) {
        ((Y) this.b).n.getClass();
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        AtomicLong atomicLong = (AtomicLong) this.d;
        if (atomicLong.get() != -1 && jElapsedRealtime - atomicLong.get() <= 1800000) {
            return;
        }
        ((com.google.android.gms.common.internal.service.b) this.c).d(new TelemetryData(0, Arrays.asList(new MethodInvocation(36301, i, 0, j, j2, null, null, 0, i2)))).o(new l1(this, jElapsedRealtime, 13));
    }

    @Override // io.ktor.client.plugins.InterfaceC4874v
    public void a(Object obj, io.ktor.client.c client) {
        e plugin = (e) obj;
        Intrinsics.checkNotNullParameter(plugin, "plugin");
        Intrinsics.checkNotNullParameter(client, "scope");
        plugin.getClass();
        Intrinsics.checkNotNullParameter(client, "scope");
        c cVar = new c(plugin.a, client, plugin.b);
        plugin.c.invoke(cVar);
        plugin.d = cVar.d;
        Iterator it2 = cVar.c.iterator();
        while (it2.hasNext()) {
            f fVar = (f) it2.next();
            fVar.getClass();
            Intrinsics.checkNotNullParameter(client, "client");
            fVar.a.c(client, fVar.b);
        }
    }

    @Override // io.ktor.client.plugins.InterfaceC4874v
    public Object b(Function1 block) {
        Intrinsics.checkNotNullParameter(block, "block");
        Object objInvoke = ((Function0) this.b).invoke();
        block.invoke(objInvoke);
        return new e((io.ktor.util.a) this.d, objInvoke, (Function1) this.c);
    }

    @Override // com.bumptech.glide.load.resource.bitmap.v
    public int c() {
        ByteBuffer byteBufferC = com.bumptech.glide.util.b.c((ByteBuffer) this.b);
        androidx.compose.foundation.lazy.grid.m mVar = (androidx.compose.foundation.lazy.grid.m) this.d;
        if (byteBufferC != null) {
            ArrayList arrayList = (ArrayList) this.c;
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                try {
                    int iD = ((com.bumptech.glide.load.d) arrayList.get(i)).d(byteBufferC, mVar);
                    if (iD != -1) {
                        return iD;
                    }
                } finally {
                }
            }
        }
        return -1;
    }

    @Override // com.bumptech.glide.load.resource.bitmap.v
    public Bitmap d(BitmapFactory.Options options) {
        return BitmapFactory.decodeStream(new com.bumptech.glide.util.a(com.bumptech.glide.util.b.c((ByteBuffer) this.b)), null, options);
    }

    @Override // com.bumptech.glide.load.resource.bitmap.v
    public void e() {
    }

    @Override // com.bumptech.glide.load.resource.bitmap.v
    public ImageHeaderParser$ImageType f() {
        return AbstractC3567z.c((ArrayList) this.c, com.bumptech.glide.util.b.c((ByteBuffer) this.b));
    }

    @Override // io.ktor.client.plugins.InterfaceC4874v
    public io.ktor.util.a getKey() {
        return (io.ktor.util.a) this.d;
    }

    public void h(k kVar, Map.Entry entry) {
        k kVar2 = (k) entry.getValue();
        C0155g c0155g = null;
        C0155g c0155g2 = new C0155g(kVar.g.a, ((androidx.camera.core.processing.util.b) entry.getKey()).d, kVar.c ? (InterfaceC0185y) this.c : null, ((androidx.camera.core.processing.util.b) entry.getKey()).f, ((androidx.camera.core.processing.util.b) entry.getKey()).g);
        int i = ((androidx.camera.core.processing.util.b) entry.getKey()).c;
        kVar2.getClass();
        S.d();
        kVar2.a();
        AbstractC3242q6.h("Consumer can only be linked once.", !kVar2.j);
        kVar2.j = true;
        j jVar = kVar2.l;
        androidx.camera.core.impl.utils.futures.b bVarF = androidx.camera.core.impl.utils.futures.i.f(jVar.c(), new androidx.camera.core.processing.i(kVar2, jVar, i, c0155g2, c0155g), T.e());
        bVarF.a(new androidx.camera.core.impl.utils.futures.h(0, bVarF, new com.quizlet.data.repository.explanations.myexplanations.a(2, this, kVar2)), T.e());
    }

    public io.reactivex.rxjava3.internal.operators.single.g j(String str, Map request) {
        Intrinsics.checkNotNullParameter(request, "request");
        io.reactivex.rxjava3.internal.operators.single.g gVarG = ((IQuizletApiClient) this.b).g(request).g(new u(this, false, str, 22));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return gVarG;
    }

    public io.reactivex.rxjava3.internal.operators.single.g k(Map request) {
        Intrinsics.checkNotNullParameter(request, "request");
        io.reactivex.rxjava3.internal.operators.single.g gVarG = ((IQuizletApiClient) this.b).j(request).g(new com.lyft.android.scissors.b(this, 27));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return gVarG;
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x00a9  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00ae  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.android.billingclient.api.d l() throws java.lang.Throwable {
        /*
            r8 = this;
            com.google.firebase.crashlytics.internal.concurrency.d.b()
            r0 = 0
            java.lang.Object r1 = r8.b     // Catch: java.lang.Throwable -> La5
            java.lang.String r1 = (java.lang.String) r1     // Catch: java.lang.Throwable -> La5
            java.lang.Object r2 = r8.c     // Catch: java.lang.Throwable -> La5
            java.util.HashMap r2 = (java.util.HashMap) r2     // Catch: java.lang.Throwable -> La5
            java.lang.String r1 = i(r2, r1)     // Catch: java.lang.Throwable -> L9f
            java.lang.String r2 = "FirebaseCrashlytics"
            r3 = 2
            android.util.Log.isLoggable(r2, r3)     // Catch: java.lang.Throwable -> La2
            java.net.URL r2 = new java.net.URL     // Catch: java.lang.Throwable -> L9f
            r2.<init>(r1)     // Catch: java.lang.Throwable -> L9f
            java.net.URLConnection r1 = r2.openConnection()     // Catch: java.lang.Throwable -> L9f
            javax.net.ssl.HttpsURLConnection r1 = (javax.net.ssl.HttpsURLConnection) r1     // Catch: java.lang.Throwable -> L9f
            r2 = 10000(0x2710, float:1.4013E-41)
            r1.setReadTimeout(r2)     // Catch: java.lang.Throwable -> L56
            r1.setConnectTimeout(r2)     // Catch: java.lang.Throwable -> L56
            java.lang.String r2 = "GET"
            r1.setRequestMethod(r2)     // Catch: java.lang.Throwable -> L56
            java.lang.Object r2 = r8.d     // Catch: java.lang.Throwable -> L56
            java.util.HashMap r2 = (java.util.HashMap) r2     // Catch: java.lang.Throwable -> L56
            java.util.Set r2 = r2.entrySet()     // Catch: java.lang.Throwable -> L56
            java.util.Iterator r2 = r2.iterator()     // Catch: java.lang.Throwable -> L56
        L3a:
            boolean r3 = r2.hasNext()     // Catch: java.lang.Throwable -> L56
            if (r3 == 0) goto L58
            java.lang.Object r3 = r2.next()     // Catch: java.lang.Throwable -> L56
            java.util.Map$Entry r3 = (java.util.Map.Entry) r3     // Catch: java.lang.Throwable -> L56
            java.lang.Object r4 = r3.getKey()     // Catch: java.lang.Throwable -> L56
            java.lang.String r4 = (java.lang.String) r4     // Catch: java.lang.Throwable -> L56
            java.lang.Object r3 = r3.getValue()     // Catch: java.lang.Throwable -> L56
            java.lang.String r3 = (java.lang.String) r3     // Catch: java.lang.Throwable -> L56
            r1.addRequestProperty(r4, r3)     // Catch: java.lang.Throwable -> L56
            goto L3a
        L56:
            r2 = move-exception
            goto La7
        L58:
            r1.connect()     // Catch: java.lang.Throwable -> L56
            int r2 = r1.getResponseCode()     // Catch: java.lang.Throwable -> L56
            java.io.InputStream r3 = r1.getInputStream()     // Catch: java.lang.Throwable -> L56
            if (r3 == 0) goto L91
            java.io.BufferedReader r0 = new java.io.BufferedReader     // Catch: java.lang.Throwable -> L8d
            java.io.InputStreamReader r4 = new java.io.InputStreamReader     // Catch: java.lang.Throwable -> L8d
            java.lang.String r5 = "UTF-8"
            r4.<init>(r3, r5)     // Catch: java.lang.Throwable -> L8d
            r0.<init>(r4)     // Catch: java.lang.Throwable -> L8d
            r4 = 8192(0x2000, float:1.148E-41)
            char[] r4 = new char[r4]     // Catch: java.lang.Throwable -> L8d
            java.lang.StringBuilder r5 = new java.lang.StringBuilder     // Catch: java.lang.Throwable -> L8d
            r5.<init>()     // Catch: java.lang.Throwable -> L8d
        L7a:
            int r6 = r0.read(r4)     // Catch: java.lang.Throwable -> L8d
            r7 = -1
            if (r6 == r7) goto L86
            r7 = 0
            r5.append(r4, r7, r6)     // Catch: java.lang.Throwable -> L8d
            goto L7a
        L86:
            java.lang.String r0 = r5.toString()     // Catch: java.lang.Throwable -> L8d
            goto L91
        L8b:
            r2 = r0
            goto L8f
        L8d:
            r0 = move-exception
            goto L8b
        L8f:
            r0 = r3
            goto La7
        L91:
            if (r3 == 0) goto L96
            r3.close()
        L96:
            r1.disconnect()
            com.android.billingclient.api.d r1 = new com.android.billingclient.api.d
            r1.<init>(r2, r0)
            return r1
        L9f:
            r2 = move-exception
        La0:
            r1 = r0
            goto La7
        La2:
            r1 = move-exception
        La3:
            r2 = r1
            goto La0
        La5:
            r1 = move-exception
            goto La3
        La7:
            if (r0 == 0) goto Lac
            r0.close()
        Lac:
            if (r1 == 0) goto Lb1
            r1.disconnect()
        Lb1:
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.api.d.l():com.android.billingclient.api.d");
    }

    public E m(G loadType) {
        Intrinsics.checkNotNullParameter(loadType, "loadType");
        int iOrdinal = loadType.ordinal();
        if (iOrdinal == 0) {
            return (E) this.b;
        }
        if (iOrdinal == 1) {
            return (E) this.c;
        }
        if (iOrdinal == 2) {
            return (E) this.d;
        }
        throw new NoWhenBranchMatchedException();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0067, code lost:
    
        if (r0.equals("oauth_email_has_multiple_accounts") == false) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x0071, code lost:
    
        if (r0.equals("exception_missing_magic_link_code") == false) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x007a, code lost:
    
        if (r0.equals("oauth_email_in_use") == false) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x007f, code lost:
    
        if (r11 == null) goto L44;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x0081, code lost:
    
        r10 = r11.getExistingUsername();
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x0086, code lost:
    
        r10 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x0087, code lost:
    
        if (r11 == null) goto L47;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x0089, code lost:
    
        r12 = r11.getExistingMaskedEmail();
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x008e, code lost:
    
        r12 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x008f, code lost:
    
        if (r10 == null) goto L51;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x0091, code lost:
    
        if (r12 == null) goto L51;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x0093, code lost:
    
        r1 = new com.quizlet.login.authentication.data.f(r10, r12, r11.getExistingProfileImage(), r11.isExistingUserIsPlus());
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x00a3, code lost:
    
        return new com.quizlet.login.authentication.data.a(r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00aa, code lost:
    
        if (r0.equals("exception_magic_link_user_not_found") == false) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x00b3, code lost:
    
        if (r0.equals("exception_magic_link_already_used") == false) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x00bc, code lost:
    
        if (r0.equals("exception_magic_link_canceled") == false) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x00c5, code lost:
    
        if (r0.equals("exception_magic_link_code_expired") == false) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x00ca, code lost:
    
        return com.quizlet.login.authentication.data.g.a;
     */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:13:0x0024  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.quizlet.login.authentication.data.i n(java.lang.String r9, java.util.List r10, com.quizlet.api.model.Authentication r11, com.quizlet.api.model.ServerProvidedError r12) {
        /*
            Method dump skipped, instructions count: 338
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.api.d.n(java.lang.String, java.util.List, com.quizlet.api.model.Authentication, com.quizlet.api.model.ServerProvidedError):com.quizlet.login.authentication.data.i");
    }

    public io.reactivex.rxjava3.core.i o(long j, p stopToken) {
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        Long lValueOf = Long.valueOf(j);
        com.quizlet.cache.a aVar = (com.quizlet.cache.a) this.d;
        io.reactivex.rxjava3.core.i iVar = (io.reactivex.rxjava3.core.i) aVar.get(lValueOf);
        if (iVar != null) {
            return iVar;
        }
        C4905y c4905y = new C4905y(new C4896o(new io.reactivex.rxjava3.internal.operators.mixed.b(((androidx.work.impl.model.c) this.c).b(stopToken, new C1510p(this, j, 7)))), new com.quizlet.data.interactor.base.a(aVar, lValueOf, 0), 1);
        Intrinsics.checkNotNullExpressionValue(c4905y, "doFinally(...)");
        aVar.a(lValueOf, c4905y);
        return c4905y;
    }

    @Override // okhttp3.InterfaceC5077f
    public void onFailure(InterfaceC5076e call, IOException e2) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(e2, "e");
        ((com.quizlet.shared.httpclient.f) this.b).invoke(new com.quizlet.shared.httpclient.a(new NetworkErrorException(null, e2)));
    }

    @Override // okhttp3.InterfaceC5077f
    public void onResponse(InterfaceC5076e call, H okHttpResponse) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(okHttpResponse, "okHttpResponse");
        ((com.quizlet.shared.httpclient.f) this.c).invoke(com.quizlet.remote.kmp.a.a((com.quizlet.remote.kmp.a) this.d, okHttpResponse));
    }

    public Pair p(List list) throws NoRecommendationsException {
        o iVar;
        List listA = C4168t1.a(list, new Z(3));
        if (listA == null && (listA = C4168t1.a(list, new Z(2))) == null) {
            listA = kotlin.collections.K.a;
        }
        if (listA.isEmpty()) {
            throw new NoRecommendationsException();
        }
        List listN0 = CollectionsKt.n0(listA, new com.google.zxing.aztec.encoder.c(15));
        ArrayList arrayList = new ArrayList(C.q(listN0, 10));
        Iterator it2 = listN0.iterator();
        while (true) {
            if (!it2.hasNext()) {
                List listA2 = C4168t1.a(list, new Z(3));
                return new Pair((listA2 == null || !(listA2.isEmpty() ^ true)) ? z0.b : z0.a, AbstractC3409x1.i(arrayList));
            }
            N1 input = (N1) it2.next();
            C0429a c0429a = (C0429a) this.d;
            Intrinsics.checkNotNullParameter(input, "input");
            boolean z = input instanceof StudyMaterialItem$FlashcardSetItem;
            long j = c0429a.a;
            if (z) {
                StudySetWithCreator studySetWithCreator = ((StudyMaterialItem$FlashcardSetItem) input).b;
                User user = studySetWithCreator.b;
                iVar = new com.quizlet.ui.models.content.listitem.l(T5.c(studySetWithCreator.a, user != null ? user.b : null, user != null && user.a == j), ((StudyMaterialItem$FlashcardSetItem) input).a.c(), 0L, 28);
            } else if (input instanceof StudyMaterialItem$FolderItem) {
                iVar = new com.quizlet.ui.models.content.listitem.h(U5.c(((StudyMaterialItem$FolderItem) input).b.a), ((StudyMaterialItem$FolderItem) input).a.c(), 0L, 28);
            } else if (input instanceof StudyMaterialItem$TextbookItem) {
                iVar = new n(W5.c(((StudyMaterialItem$TextbookItem) input).b), ((StudyMaterialItem$TextbookItem) input).a.c(), 0L, 28);
            } else if (input instanceof StudyMaterialItem$TextbookExerciseItem) {
                iVar = new com.quizlet.ui.models.content.listitem.m(X5.f(((StudyMaterialItem$TextbookExerciseItem) input).b), ((StudyMaterialItem$TextbookExerciseItem) input).a.c(), 0L, 28);
            } else if (input instanceof StudyMaterialItem$ExplanationQuestionItem) {
                Question question = ((StudyMaterialItem$ExplanationQuestionItem) input).b;
                Intrinsics.checkNotNullParameter(question, "<this>");
                String str = question.f.a;
                if (str == null) {
                    str = "";
                }
                iVar = new com.quizlet.ui.models.content.listitem.k(new com.quizlet.ui.models.content.listitem.c(question.d, str), ((StudyMaterialItem$ExplanationQuestionItem) input).a.c(), 0L, 28);
            } else {
                if (!(input instanceof StudyMaterialItem$NoteItem)) {
                    throw new NoWhenBranchMatchedException();
                }
                iVar = new com.quizlet.ui.models.content.listitem.i(V5.e(((StudyMaterialItem$NoteItem) input).b, j), ((StudyMaterialItem$NoteItem) input).a.c(), 0L, 28);
            }
            arrayList.add(iVar);
        }
    }

    public String[] q() {
        EnumSet enumSet = (EnumSet) this.b;
        String[] strArr = new String[enumSet.size()];
        Iterator it2 = enumSet.iterator();
        int i = 0;
        while (it2.hasNext()) {
            strArr[i] = ((com.snowplowanalytics.core.emitter.d) it2.next()).toString();
            i++;
        }
        return strArr;
    }

    public void r(String str, String str2) {
        ((HashMap) this.d).put(str, str2);
    }

    public boolean s() {
        if (((androidx.compose.ui.text.font.H) this.b).getValue() != this.d) {
            return true;
        }
        d dVar = (d) this.c;
        return dVar != null && dVar.s();
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x0071, code lost:
    
        if (r8 == r1) goto L31;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable t(long r7, kotlin.coroutines.jvm.internal.c r9) {
        /*
            r6 = this;
            boolean r0 = r9 instanceof com.quizlet.features.folders.viewmodel.usecases.i
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.features.folders.viewmodel.usecases.i r0 = (com.quizlet.features.folders.viewmodel.usecases.i) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.features.folders.viewmodel.usecases.i r0 = new com.quizlet.features.folders.viewmodel.usecases.i
            r0.<init>(r6, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L46
            if (r2 == r4) goto L3a
            if (r2 != r3) goto L32
            io.ktor.client.plugins.api.d r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Exception -> L30
            com.quizlet.data.model.t1 r9 = (com.quizlet.data.model.C4168t1) r9     // Catch: java.lang.Exception -> L30
            java.util.List r8 = r9.a     // Catch: java.lang.Exception -> L30
            goto L74
        L30:
            r7 = move-exception
            goto L89
        L32:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L3a:
            long r7 = r0.k
            io.ktor.client.plugins.api.d r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Exception -> L30
            r5 = r2
            r2 = r9
            r8 = r7
            r7 = r5
            goto L5d
        L46:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r6.b     // Catch: java.lang.Exception -> L30
            com.quizlet.data.repository.course.membership.c r9 = (com.quizlet.data.repository.course.membership.c) r9     // Catch: java.lang.Exception -> L30
            r0.j = r6     // Catch: java.lang.Exception -> L30
            r0.k = r7     // Catch: java.lang.Exception -> L30
            r0.n = r4     // Catch: java.lang.Exception -> L30
            java.lang.Object r9 = r9.d(r0)     // Catch: java.lang.Exception -> L30
            if (r9 != r1) goto L5a
            goto L73
        L5a:
            r2 = r9
            r8 = r7
            r7 = r6
        L5d:
            java.lang.Boolean r2 = (java.lang.Boolean) r2     // Catch: java.lang.Exception -> L30
            boolean r2 = r2.booleanValue()     // Catch: java.lang.Exception -> L30
            if (r2 == 0) goto L7d
            java.lang.Object r2 = r7.c     // Catch: java.lang.Exception -> L30
            com.quizlet.data.interactor.folder.c r2 = (com.quizlet.data.interactor.folder.c) r2     // Catch: java.lang.Exception -> L30
            r0.j = r7     // Catch: java.lang.Exception -> L30
            r0.n = r3     // Catch: java.lang.Exception -> L30
            java.lang.Object r8 = r2.a(r8, r0)     // Catch: java.lang.Exception -> L30
            if (r8 != r1) goto L74
        L73:
            return r1
        L74:
            java.util.List r8 = (java.util.List) r8     // Catch: java.lang.Exception -> L30
            kotlin.Pair r7 = r7.p(r8)     // Catch: java.lang.Exception -> L30
            kotlin.p r8 = kotlin.r.b     // Catch: java.lang.Exception -> L30
            return r7
        L7d:
            kotlin.p r7 = kotlin.r.b     // Catch: java.lang.Exception -> L30
            com.quizlet.features.folders.viewmodel.usecases.FeatureDisabledException r7 = new com.quizlet.features.folders.viewmodel.usecases.FeatureDisabledException     // Catch: java.lang.Exception -> L30
            r7.<init>()     // Catch: java.lang.Exception -> L30
            kotlin.q r7 = androidx.glance.appwidget.protobuf.Z.b(r7)     // Catch: java.lang.Exception -> L30
            return r7
        L89:
            kotlin.p r8 = kotlin.r.b
            kotlin.q r7 = androidx.glance.appwidget.protobuf.Z.b(r7)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.api.d.t(long, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public String toString() {
        switch (this.a) {
            case 9:
                StringBuilder sb = new StringBuilder("FilterIconProperty{, contentDescription='");
                sb.append((String) this.b);
                sb.append("', selectedARIALabelStatus='");
                sb.append((String) this.c);
                sb.append("', unselectedARIALabelStatus='");
                return android.support.v4.media.session.a.t(sb, (String) this.d, "'}");
            default:
                return super.toString();
        }
    }

    public Object u(String str, DBUser dBUser, boolean z, kotlin.coroutines.jvm.internal.c cVar) {
        com.quizlet.infra.legacysyncengine.managers.d dVar = (com.quizlet.infra.legacysyncengine.managers.d) this.b;
        dVar.getClass();
        long id = dBUser.getId();
        UserInfoCacheKt.a(dVar.e, dBUser);
        dVar.f.b(str);
        dVar.d(dBUser);
        DatabaseHelper databaseHelper = dVar.b;
        databaseHelper.getClass();
        dVar.c.f(new com.quizlet.db.data.database.a(databaseHelper, id, 0));
        com.quizlet.data.repository.widget.b bVar = dVar.m;
        bVar.getClass();
        new io.reactivex.rxjava3.internal.operators.completable.c(new androidx.work.impl.utils.d(bVar, 11), 4).h((io.reactivex.rxjava3.core.o) bVar.c).e();
        io.reactivex.rxjava3.subjects.f fVarB = dVar.b(id);
        ((com.quizlet.braze.e) this.c).a(dBUser);
        com.quizlet.quizletandroid.ui.login.authmanagers.a aVar = new com.quizlet.quizletandroid.ui.login.authmanagers.a(z, dBUser, this, 0);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        io.reactivex.rxjava3.internal.operators.completable.i iVar = new io.reactivex.rxjava3.internal.operators.completable.i(fVarB, gVar, gVar, aVar, io.reactivex.rxjava3.internal.functions.d.c);
        Intrinsics.checkNotNullExpressionValue(iVar, "doOnComplete(...)");
        Object objA = I1.a(iVar, cVar);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : Unit.a;
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x006b, code lost:
    
        if (r6 == r1) goto L26;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable v(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.features.setpage.termlist.ads.f
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.features.setpage.termlist.ads.f r0 = (com.quizlet.features.setpage.termlist.ads.f) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.features.setpage.termlist.ads.f r0 = new com.quizlet.features.setpage.termlist.ads.f
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L6e
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L32:
            io.ktor.client.plugins.api.d r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L53
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.m = r4
            java.lang.Object r6 = r5.b
            com.quizlet.shared.usecase.studiableMetadata.a r6 = (com.quizlet.shared.usecase.studiableMetadata.a) r6
            java.lang.Object r2 = r5.c
            androidx.work.impl.model.c r2 = (androidx.work.impl.model.c) r2
            io.reactivex.rxjava3.core.p r6 = r6.l(r2)
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r6, r0)
            if (r6 != r1) goto L52
            goto L6d
        L52:
            r2 = r5
        L53:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 != 0) goto L5e
            kotlin.collections.K r6 = kotlin.collections.K.a
            return r6
        L5e:
            java.lang.Object r6 = r2.d
            androidx.work.impl.model.i r6 = (androidx.work.impl.model.i) r6
            r2 = 0
            r0.j = r2
            r0.m = r3
            java.lang.Object r6 = r6.g(r0)
            if (r6 != r1) goto L6e
        L6d:
            return r1
        L6e:
            java.lang.Iterable r6 = (java.lang.Iterable) r6
            java.util.ArrayList r0 = new java.util.ArrayList
            r1 = 10
            int r1 = kotlin.collections.C.q(r6, r1)
            r0.<init>(r1)
            java.util.Iterator r6 = r6.iterator()
        L7f:
            boolean r1 = r6.hasNext()
            if (r1 == 0) goto L94
            java.lang.Object r1 = r6.next()
            com.quizlet.features.setpage.termlist.ads.a r1 = (com.quizlet.features.setpage.termlist.ads.a) r1
            com.quizlet.features.setpage.termlist.data.i r2 = new com.quizlet.features.setpage.termlist.data.i
            r2.<init>(r1)
            r0.add(r2)
            goto L7f
        L94:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.api.d.v(kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public void w(DBTerm term, O1 termSide) {
        Intrinsics.checkNotNullParameter(term, "term");
        Intrinsics.checkNotNullParameter(termSide, "termSide");
        LinkedHashMap linkedHashMap = (LinkedHashMap) this.d;
        Boolean bool = (Boolean) linkedHashMap.get(termSide);
        if (bool == null || !bool.booleanValue()) {
            Intrinsics.checkNotNullParameter(term, "term");
            Intrinsics.checkNotNullParameter(termSide, "termSide");
            linkedHashMap.put(termSide, Boolean.valueOf(A(new com.quizlet.quizletandroid.managers.audio.c(termSide == O1.WORD ? R.string.this_term : R.string.this_definition, term.getId(), term.getText(termSide), term.getLanguageCode(termSide)))));
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0048  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.quizlet.login.authentication.data.i x(java.lang.String r9, java.lang.Throwable r10) {
        /*
            Method dump skipped, instructions count: 251
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: io.ktor.client.plugins.api.d.x(java.lang.String, java.lang.Throwable):com.quizlet.login.authentication.data.i");
    }

    public void y(F states) {
        Intrinsics.checkNotNullParameter(states, "states");
        this.b = states.a;
        this.d = states.c;
        this.c = states.b;
    }

    public void z(G type, E state) {
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(state, "state");
        int iOrdinal = type.ordinal();
        if (iOrdinal == 0) {
            this.b = state;
        } else if (iOrdinal == 1) {
            this.c = state;
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            this.d = state;
        }
    }

    public d(Context context, Y y) {
        this.a = 7;
        this.d = new AtomicLong(-1L);
        this.c = com.google.android.gms.common.internal.u.n(context, new com.google.android.gms.common.internal.k("measurement:api"));
        this.b = y;
    }

    public d(com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, com.quizlet.braze.e brazeUserManager, com.quizlet.data.repository.set.f userNotificationManager) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(brazeUserManager, "brazeUserManager");
        Intrinsics.checkNotNullParameter(userNotificationManager, "userNotificationManager");
        this.b = loggedInUserManager;
        this.c = brazeUserManager;
        this.d = userNotificationManager;
    }

    public d(y service, com.quizlet.data.repository.user.a remoteSearchAllResultsMapper, AbstractC5040y ioDispatcher) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(remoteSearchAllResultsMapper, "remoteSearchAllResultsMapper");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = service;
        this.c = remoteSearchAllResultsMapper;
        this.d = ioDispatcher;
    }

    public d(com.quizlet.data.repository.studysetwithcreator.d repository, androidx.work.impl.model.c dispatcher, com.quizlet.cache.a requestCache) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(requestCache, "requestCache");
        this.b = repository;
        this.c = dispatcher;
        this.d = requestCache;
    }

    public d(com.quizlet.shared.usecase.studiableMetadata.a globalAdFeature, androidx.work.impl.model.c userProperties, androidx.work.impl.model.i termsListAdFetcher) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(globalAdFeature, "globalAdFeature");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(termsListAdFetcher, "termsListAdFetcher");
        this.b = globalAdFeature;
        this.c = userProperties;
        this.d = termsListAdFetcher;
    }

    public d(com.quizlet.data.repository.course.membership.c coursePoweredFoldersFeature, com.quizlet.data.interactor.folder.c getFolderRecommendationsUseCase, C0429a folderStudyMaterialMapper) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(coursePoweredFoldersFeature, "coursePoweredFoldersFeature");
        Intrinsics.checkNotNullParameter(getFolderRecommendationsUseCase, "getFolderRecommendationsUseCase");
        Intrinsics.checkNotNullParameter(folderStudyMaterialMapper, "folderStudyMaterialMapper");
        this.b = coursePoweredFoldersFeature;
        this.c = getFolderRecommendationsUseCase;
        this.d = folderStudyMaterialMapper;
    }

    public d(int i) {
        this.a = i;
        switch (i) {
            case 6:
                break;
            case 9:
                this.b = "";
                this.c = "";
                this.d = "";
                break;
            default:
                D d = D.c;
                this.b = d;
                this.c = d;
                this.d = d;
                break;
        }
    }

    public d(EnumSet tlsVersions) throws NoSuchAlgorithmException, KeyStoreException {
        this.a = 18;
        Intrinsics.checkNotNullParameter(tlsVersions, "tlsVersions");
        this.b = tlsVersions;
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init((KeyStore) null);
            TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
            if (trustManagers.length == 1) {
                TrustManager trustManager = trustManagers[0];
                if (trustManager instanceof X509TrustManager) {
                    Intrinsics.e(trustManager, "null cannot be cast to non-null type javax.net.ssl.X509TrustManager");
                    X509TrustManager x509TrustManager = (X509TrustManager) trustManager;
                    Intrinsics.checkNotNullParameter(x509TrustManager, "<set-?>");
                    this.c = x509TrustManager;
                    C1881be c1881be = new C1881be(q());
                    Intrinsics.checkNotNullParameter(c1881be, "<set-?>");
                    this.d = c1881be;
                    return;
                }
            }
            throw new IllegalStateException(("Unexpected default trust managers:" + Arrays.toString(trustManagers)).toString());
        } catch (KeyManagementException e2) {
            e2.printStackTrace();
        } catch (KeyStoreException e3) {
            e3.printStackTrace();
        } catch (NoSuchAlgorithmException e4) {
            e4.printStackTrace();
        }
    }

    public d(Context context, com.quizlet.quizletandroid.util.f languageUtil) {
        int i;
        this.a = 14;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(languageUtil, "languageUtil");
        this.b = context;
        this.c = languageUtil;
        this.d = new LinkedHashMap();
        int i2 = 4;
        while (true) {
            i = 80;
            if (i2 >= 32) {
                break;
            }
            int i3 = (1 << i2) - 12;
            if (80 <= i3) {
                i = i3;
                break;
            }
            i2++;
        }
        int i4 = i / 8;
        long[] jArr = new long[i4];
        Object[] objArr = new Object[i4];
    }

    public d(HashMap map, String str) {
        this.a = 8;
        this.b = str;
        this.c = map;
        this.d = new HashMap();
    }

    public d(IQuizletApiClient apiClient, OneOffAPIParser oneOffAPIParser, ApiErrorResolverWrapper apiErrorResolverWrapper) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(apiClient, "apiClient");
        Intrinsics.checkNotNullParameter(oneOffAPIParser, "oneOffAPIParser");
        Intrinsics.checkNotNullParameter(apiErrorResolverWrapper, "apiErrorResolverWrapper");
        this.b = apiClient;
        this.c = oneOffAPIParser;
        this.d = apiErrorResolverWrapper;
    }

    public d(Throwable th, String str, Object[] objArr) {
        this.a = 19;
        this.b = str;
        this.c = th;
        this.d = objArr;
    }

    public d(String name, Function0 createConfiguration, Function1 body) {
        U uB;
        this.a = 0;
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(createConfiguration, "createConfiguration");
        Intrinsics.checkNotNullParameter(body, "body");
        this.b = createConfiguration;
        this.c = body;
        C4950i c4950iA = kotlin.jvm.internal.K.a(e.class);
        try {
            q qVar = KTypeProjection.c;
            C4950i c4950iA2 = kotlin.jvm.internal.K.a(d.class);
            s sVar = s.a;
            L l = kotlin.jvm.internal.K.a;
            l.getClass();
            Q q = new Q(c4950iA2);
            kotlin.jvm.internal.K.b(q, kotlin.jvm.internal.K.c(Object.class));
            U uB2 = L.b(q, Collections.EMPTY_LIST);
            qVar.getClass();
            KTypeProjection kTypeProjectionA = q.a(uB2);
            C4950i c4950iA3 = kotlin.jvm.internal.K.a(e.class);
            List listSingletonList = Collections.singletonList(kTypeProjectionA);
            l.getClass();
            uB = L.b(c4950iA3, listSingletonList);
        } catch (Throwable unused) {
            uB = null;
        }
        this.d = new io.ktor.util.a(name, new io.ktor.util.reflect.a(c4950iA, uB));
    }

    public d(InterfaceC0185y interfaceC0185y, androidx.camera.core.processing.c cVar) {
        this.a = 1;
        this.c = interfaceC0185y;
        this.b = cVar;
    }

    public d(androidx.compose.ui.text.font.H h, d dVar) {
        this.a = 2;
        this.b = h;
        this.c = dVar;
        this.d = h.getValue();
    }
}
